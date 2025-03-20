/*
** Copyright (C) 2025 ENEO TECNOLOGIA S.L, Inc.
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

/* include pfring */
#include <pfring.h>
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

#define DAQ_PF_RING_VERSION 1

#define PCAP_DEFAULT_POOL_SIZE 16

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

static void pfring_daq_reset_stats(void *handle);


static DAQ_BaseAPI_t daq_base_api;
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

static void destroy_packet_pool()
{
  return NULL;
}

static int create_packet_pool(unsigned size)
{
  return NULL;
}

static int update_hw_stats()
{
  return NULL;
}

static inline int set_nonblocking(bool nonblocking)
{
  return NULL;
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

static int pfring_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    return NULL;
}

static int pfring_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr) {
    unsigned snaplen = 1500;
    unsigned promisc = PF_RING_PROMISC;
    int cluster_id = 0;
    int cluster_per_flow = 0;

    PFRINGContext *ctx = (PFRINGContext *)malloc(sizeof(PFRINGContext));

    ctx->device = strdup(daq_base_api.config_get_input(modcfg));
    fprintf(stdout, "got device -> %s", ctx->device);
    if (!ctx->device)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the device string!", __func__);
        free(ctx);
        return DAQ_ERROR_NOMEM;
    }

    pfring *ring = pfring_open(ctx->device, snaplen, promisc);
    if (!ring) {
        return DAQ_ERROR;
    }

    if (cluster_id > 0) {
        if (pfring_set_cluster(ring, cluster_id, cluster_per_flow ? cluster_per_flow : cluster_id) != 0) {
            pfring_close(ring);
            return DAQ_ERROR;
        }
    }

    ctx->ring = ring;
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    ctx->pool.freelist = NULL;
    ctx->pool.info.available = 0;

    if (!ctx) {
        pfring_close(ring);
        return DAQ_ERROR;
    }

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
        return DAQ_ERROR;
    }
    return DAQ_SUCCESS;
}

static int pfring_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len) {
    if (!handle) return DAQ_ERROR;
    PFRINGContext *ctx = (PFRINGContext *)handle;
    if (pfring_send(ctx->ring, data, data_len, 1) < 0)
        return DAQ_ERROR;
    return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
    if (!handle) {
        return DAQ_ERROR;
    }
    PFRINGContext *ctx = (PFRINGContext *)handle;
    if (ctx->ring)
        pfring_close(ctx->ring);
    return DAQ_SUCCESS;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    if (!handle || !stats)
        return DAQ_ERROR;
    PFRINGContext *ctx = (PFRINGContext *)handle;
    pfring_stat ring_stats;
    if (pfring_stats(ctx->ring, &ring_stats) != 0)
        return DAQ_ERROR;
    memcpy(stats->verdicts, ctx->stats.verdicts, sizeof(ctx->stats.verdicts));
    return DAQ_SUCCESS;
}

static int pfring_daq_interrupt(void *handle) {
    if (!handle) {
        return DAQ_ERROR;
    }
    PFRINGContext *ctx = (PFRINGContext *)handle;
    pfring_breakloop(ctx->ring);
    return DAQ_SUCCESS;
}

static void pfring_daq_reset_stats(void *handle)
{
  return NULL;
}

static int pfring_daq_get_snaplen(void *handle)
{
  return NULL;
}

static uint32_t pfring_daq_get_capabilities(void *handle)
{
  return NULL;
}

static int pfring_daq_get_datalink_type(void *handle)
{
  return DLT_EN10MB;
}

static unsigned pfring_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat) {
    if (!handle) {
        fprintf(stderr, "pfring_daq_msg_receive: Invalid handle\n");
        return 0;
    }
    PFRINGContext *ctx = (PFRINGContext *)handle;
    unsigned idx = 0;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;

    while (idx < max_recv) {
        /* Get a descriptor from the free pool */
        PFRINGPktDesc *desc = ctx->pool.freelist;
        if (!desc) {
            status = DAQ_RSTAT_NOBUF;
            break;
        }

        char *pkt_data = NULL;
        uint32_t recv_len = 0;
        struct timespec ts;
        /* Receive one packet; wait_for_packet flag set to 1 */
        int rc = pfring_recv(ctx->ring, &pkt_data, &recv_len, &ts, 1);
        if (rc <= 0) {
            status = DAQ_RSTAT_WOULD_BLOCK;
            break;
        }
        /* rc should equal recv_len; we now have a packet of length recv_len */

        /* Allocate (or reuse) a buffer for the packet data.
           In a production system you might use a preallocated buffer instead. */
        desc->data = malloc(recv_len);
        if (!desc->data) {
            status = DAQ_RSTAT_NOBUF;
            break;
        }
        memcpy(desc->data, pkt_data, recv_len);
        desc->length = recv_len;

        {
            DAQ_Msg_t *msg = &desc->msg;
            msg->data_len = recv_len;
            msg->priv = desc;
        }

        {
            desc->pkthdr.ts.tv_sec = ts.tv_sec;
            desc->pkthdr.ts.tv_usec = ts.tv_nsec / 1000;
            desc->pkthdr.pktlen = recv_len;
        }

        ctx->pool.freelist = desc->next;
        desc->next = NULL;
        if (ctx->pool.info.available > 0)
            ctx->pool.info.available--;

        msgs[idx] = &desc->msg;
        idx++;
    }
    *rstat = status;
    return idx;
}

static int pfring_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict) {
    if (!handle || !msg) {
        return DAQ_ERROR;
    }
    PFRINGContext *ctx = (PFRINGContext *)handle;
    PFRINGPktDesc *desc = (PFRINGPktDesc *)msg->priv;
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    ctx->stats.verdicts[verdict]++;
    verdict = verdict_translation_table[verdict];
    if (verdict == DAQ_VERDICT_PASS) {
        if (pfring_send(ctx->ring, desc->data, desc->length, 1) < 0) {
            return DAQ_ERROR;
        }
    }
    desc->next = ctx->pool.freelist;
    ctx->pool.freelist = desc;
    ctx->pool.info.available++;
    return DAQ_SUCCESS;
}

static int pfring_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
  return NULL;
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
