/*
** Copyright (C) 2025 ENEO TECNOLOGIA S.L.
** Author: Miguel Álvarez <malvarez@redborder.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* include pfring module with dependencies */
#include <pfring.h>
#include <net/ethernet.h>

#include "daq_module_api.h"

typedef struct _pfring_pkt_desc {
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    struct _pfring_packet_instance *instance;
    unsigned int length;
    struct _pfring_pkt_desc *next;
} PFRINGPktDesc;

typedef struct _pfring_context {
    pfring *ring;
    char *device;
    u_char *pkt_buffer;
    PFRINGPktDesc *pending_desc;
    DAQ_Stats_t stats;
    struct {
        PFRINGPktDesc *freelist;
        struct {
            unsigned available;
        } info;
    } pool;
} PFRINGContext;

typedef struct _pfring_packet_instance {
    pfring *ring;
    uint8_t direction;
} PFRINGpacketInstance;

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* 0: PASS */
    DAQ_VERDICT_BLOCK,      /* 1: BLOCK */
    DAQ_VERDICT_PASS,       /* 2: REPLACE */
    DAQ_VERDICT_PASS,       /* 3: WHITELIST */
    DAQ_VERDICT_BLOCK,      /* 4: BLACKLIST */
    DAQ_VERDICT_PASS        /* 5: IGNORE */
};

#define DAQ_PKT_FLAG_CHECKSUM_ERROR    0x0001  /* Packet has invalid checksum */
#define DAQ_PKT_FLAG_STREAM_EST        0x0002  /* Stream establishment */
#define DAQ_PKT_FLAG_STREAM_MID        0x0004  /* Mid-stream packet */
#define DAQ_PKT_FLAG_STREAM_END        0x0008  /* Stream termination */
#define DAQ_PKT_FLAG_OUTBOUND          0x0010  /* Packet is egress/outbound */
#define DAQ_PKT_FLAG_VLAN_STRIPPED     0x0020  /* VLAN tag was stripped */
#define DAQ_PKT_FLAG_MORE_FRAGMENTS    0x0040  /* More IP fragments coming */
#define DAQ_PKT_FLAG_FRAGMENT          0x0080  /* IP fragment */
#define DAQ_PKT_FLAG_IPV6              0x0100  /* IPv6 packet */
#define DAQ_PKT_FLAG_TRUNCATED         0x0200  /* Packet was truncated */
#define DAQ_PKT_FLAG_WIRE_LENGTH       0x0400  /* pktlen is wire length */
#define DAQ_PKT_FLAG_PSEUDO_CHECKSUM   0x0800  /* Checksum needs recalculation */
#define DAQ_PKT_FLAG_SESSION_KEY       0x1000  /* Contains session key material */

#define DAQ_PF_RING_VERSION 1

#define PCAP_DEFAULT_POOL_SIZE 16

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

static int pfring_daq_reset_stats(void *handle);


static DAQ_BaseAPI_t daq_base_api;
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

static int pfring_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table) {
    *var_desc_table = NULL;
    return 0;
}

static int pfring_daq_reset_stats(void *handle)
{
    if (!handle) return DAQ_ERROR;
    PFRINGContext *ctx = (PFRINGContext *)handle;
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    return DAQ_SUCCESS;
}

static int pfring_daq_get_snaplen(void *handle) {
    return (handle ? 1500 : 0);
}

static int pfring_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int pfring_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int pfring_daq_instantiate(const DAQ_ModuleConfig_h modcfg,
                                  DAQ_ModuleInstance_h modinst,
                                  void **ctxt_ptr) {
    unsigned snaplen = 1500;
    unsigned promisc = PF_RING_PROMISC;
    int cluster_id = 0;
    int cluster_per_flow = 0;

    PFRINGContext *ctx = malloc(sizeof(PFRINGContext));
    if (!ctx) {
        return DAQ_ERROR_NOMEM;
    }
    memset(ctx, 0, sizeof(PFRINGContext));

    const char *input = daq_base_api.config_get_input(modcfg);
    if (!input) {
        free(ctx);
        return DAQ_ERROR;
    }

    ctx->device = strdup(input);
    if (!ctx->device) {
        free(ctx);
        return DAQ_ERROR_NOMEM;
    }
    fprintf(stdout, "Malvads got device on daq context -> %s", ctx->device);

    pfring *ring = pfring_open(ctx->device, snaplen, promisc);
    if (!ring) {
        free(ctx->device);
        free(ctx);
        return DAQ_ERROR;
    }
    pfring_set_application_name(ring, "malvads_libdaq_pfring");
    pfring_set_socket_mode(ring, recv_only_mode);

    if (cluster_id > 0) {
        if (pfring_set_cluster(ring, cluster_id,
                               cluster_per_flow ? cluster_per_flow : cluster_id) != 0) {
            pfring_close(ring);
            free(ctx->device);
            free(ctx);
            return DAQ_ERROR;
        }
    }

    ctx->ring = ring;
    memset(&ctx->stats, 0, sizeof(ctx->stats));

    *ctxt_ptr = ctx;
    return DAQ_SUCCESS;
}

static void pfring_daq_destroy(void *handle) {
    if (handle) {
        PFRINGContext *ctx = (PFRINGContext *)handle;
        if (ctx->ring)
            pfring_close(ctx->ring);
        free(ctx);
    }
}

static int pfring_daq_set_filter(void *handle, const char *filter) {
    if (!handle || !filter) {
        return DAQ_ERROR;
    }
    PFRINGContext *ctx = (PFRINGContext *)handle;
    if (pfring_set_bpf_filter(ctx->ring, filter) != 0) {
        return DAQ_ERROR;
    }
    return DAQ_SUCCESS;
}

static int pfring_daq_start(void *handle) {
    if (!handle) {
        return DAQ_ERROR;
    }
    PFRINGContext *ctx = (PFRINGContext *)handle;
    if (pfring_enable_ring(ctx->ring) != 0) {
        pfring_close(ctx->ring);
        return DAQ_ERROR;
    }

    return DAQ_SUCCESS;
}

static int pfring_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len) {
  return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
  PFRINGContext *context =(PFRINGContext *) handle;

  pfring_close(context->ring);
  context->ring = NULL;

  return DAQ_SUCCESS;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    return DAQ_SUCCESS;
}

static int pfring_daq_interrupt(void *handle) {
  return DAQ_SUCCESS;
}

static uint32_t pfring_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK |          // Supports blocking mode
           DAQ_CAPA_INJECT |         // Supports packet injection
           DAQ_CAPA_BPF |            // Supports BPF filtering
           DAQ_CAPA_INTERRUPT;       // Can interrupt packet processing
}

static int pfring_daq_get_datalink_type(void *handle)
{
  return DLT_EN10MB;
}

void pfring_debug_print_mac_address(const u_char *addr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

#include <arpa/inet.h>

void pfring_decode_ring_packet(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) {
    if (h->len < sizeof(struct ether_header)) {
        return;
    }

    struct ether_header *eth = (struct ether_header *)p;
    printf("\nEthernet Header:\n");
    printf("   Destination: ");
    pfring_debug_print_mac_address(eth->ether_dhost);
    printf("\n   Source: ");
    pfring_debug_print_mac_address(eth->ether_shost);
    printf("\n   EtherType: 0x%04x\n", ntohs(eth->ether_type));


    printf("Packet Data (%d bytes):\n", h->len);
    for (int i = 0; i < h->len; i++) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (h->len % 16 != 0)
        printf("\n");
}


static int pfring_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat){
    PFRINGContext *pc = (PFRINGContext *)handle;
    struct pfring_pkthdr pfring_packet;
    const u_char *packet;
    unsigned idx;

    int rc = pfring_recv(pc->ring, &packet, 0, &pfring_packet, 1);

    if (rc > 0) {
        pfring_decode_ring_packet(&pfring_packet, packet, NULL);
    } else if (rc == 0) {
        usleep(1000);
    } else {
        fprintf(stderr, "Packet receive error: %d\n", rc);
    }

    *rstat = DAQ_RSTAT_OK;

    return DAQ_SUCCESS;
}

static int pfring_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict) {
  return 0;
}

static int pfring_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t pfring_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_PF_RING_VERSION,
    /* .name = */ "rb_pfring",
    /* .type = */ DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ pfring_daq_module_load,
    /* .unload = */ pfring_daq_module_unload,
    /* .get_variable_descs = */ pfring_daq_get_variable_descs,
    /* .instantiate = */ pfring_daq_instantiate,
    /* .destroy = */ pfring_daq_destroy,
    /* .set_filter = */ pfring_daq_set_filter,
    /* .start = */ pfring_daq_start,
    /* .inject = */ pfring_daq_inject,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ pfring_daq_interrupt,
    /* .stop = */ pfring_daq_stop,
    /* .ioctl = */ NULL,
    /* .get_stats = */ pfring_daq_get_stats,
    /* .reset_stats = */ pfring_daq_reset_stats,
    /* .get_snaplen = */ pfring_daq_get_snaplen,
    /* .get_capabilities = */ pfring_daq_get_capabilities,
    /* .get_datalink_type = */ pfring_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ pfring_daq_msg_receive,
    /* .msg_finalize = */ pfring_daq_msg_finalize,
    /* .get_msg_pool_info = */ pfring_daq_get_msg_pool_info,
};
