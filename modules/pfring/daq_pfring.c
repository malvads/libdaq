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

#include <pfring.h>
#include <net/ethernet.h>

#include "daq_module_api.h"
#include <pfring.h>

#define DAQ_PFRING_VERSION 1
#define PF_RING_CLUSTER_ID 0
#define DEFAULT_POOL_SIZE 32

typedef struct {
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    struct _pfring_pkt_desc *next;
} PfringPktDesc;

typedef struct {
    PfringPktDesc *pool;
    PfringPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} PfringMsgPool;

typedef struct {
    char *device;
    unsigned snaplen;
    int promisc;
    int buffer_size;
    DAQ_Mode mode;
    
    pfring *ring;
    uint32_t cluster_id;
    uint32_t cluster_type;
    
    DAQ_ModuleInstance_h modinst;
    DAQ_Stats_t stats;
    PfringMsgPool pool;
    volatile bool interrupted;

    int watermark;
    u_int8_t use_fast_tx;
    pfring_stat hw_stats;
} PfringContext;

static DAQ_BaseAPI_t daq_base_api;

static int create_packet_pool(PfringContext *pc, unsigned size) {
    PfringMsgPool *pool = &pc->pool;
    memset(pool, 0, sizeof(PfringMsgPool));
    
    pool->pool = calloc(size, sizeof(PfringPktDesc));
    if (!pool->pool) {
        return DAQ_ERROR_NOMEM;
    }
    
    pool->info.size = size;
    pool->info.available = size;
    pool->info.mem_size = size * sizeof(PfringPktDesc);

    for (unsigned i = 0; i < size; i++) {
        PfringPktDesc *desc = &pool->pool[i];
        desc->data = malloc(pc->snaplen);
        if (!desc->data) {
            for (unsigned j = 0; j < i; j++) {
                free(pool->pool[j].data);
                pool->pool[j].data = NULL;
            }
            free(pool->pool);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += pc->snaplen;
        
        desc->msg.type = DAQ_MSG_TYPE_PACKET;
        desc->msg.hdr_len = sizeof(DAQ_PktHdr_t);
        desc->msg.hdr = &desc->pkthdr;
        desc->msg.data = desc->data;
        desc->msg.owner = pc->modinst;
        desc->msg.priv = desc;

        desc->next = pool->freelist;
        pool->freelist = desc;
    }
    
    return DAQ_SUCCESS;
}

static int pfring_daq_module_load(const DAQ_BaseAPI_t *base_api) {
    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

static int pfring_daq_instantiate(const DAQ_ModuleConfig_h modcfg, 
                                 DAQ_ModuleInstance_h modinst,
                                 void **ctxt_ptr) {
    PfringContext *pc = calloc(1, sizeof(PfringContext));
    if (!pc) {
        return DAQ_ERROR_NOMEM;
    }
    
    pc->modinst = modinst;
    pc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    pc->promisc = PF_RING_PROMISC;
    const char *cluster_id_str = daq_base_api.config_get_variable(modcfg, "cluster_id");
    if (cluster_id_str) pc->cluster_id = atoi(cluster_id_str);

    const char *no_promisc = daq_base_api.config_get_variable(modcfg, "no_promisc");
    pc->promisc = no_promisc ? 0 : PF_RING_PROMISC;

    const char *cluster_mode_str = daq_base_api.config_get_variable(modcfg, "cluster_mode");
    if (cluster_mode_str) pc->cluster_type = atoi(cluster_mode_str);

    const char *watermark_str = daq_base_api.config_get_variable(modcfg, "watermark");
    if (watermark_str) pc->watermark = atoi(watermark_str);

    const char *fast_tx_str = daq_base_api.config_get_variable(modcfg, "fast_tx");
    pc->use_fast_tx = fast_tx_str ? 1 : 0;
    pc->mode = daq_base_api.config_get_mode(modcfg);

    const char *input = daq_base_api.config_get_input(modcfg);

    pc->device = strdup(input);
    if (!pc->device) {
        
        free(pc);
        return DAQ_ERROR_NOMEM;
    }
    
    int rc = create_packet_pool(pc, DEFAULT_POOL_SIZE);
    if (rc != DAQ_SUCCESS) {
        free(pc->device);
        free(pc);
        return rc;
    }
    *ctxt_ptr = pc;
    return DAQ_SUCCESS;
}

static int pfring_daq_start(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return DAQ_ERROR;
    }
    pc->ring = pfring_open(pc->device, pc->snaplen, pc->promisc);
    if (!pc->ring) { 
        daq_base_api.set_errbuf(pc->modinst, "pfring_open failed");
        return DAQ_ERROR;
    }
    pfring_set_cluster(pc->ring, pc->cluster_id, pc->cluster_type);
    pfring_set_poll_watermark(pc->ring, pc->watermark);
    pfring_set_application_name(pc->ring, "daq_pfring");
    pfring_set_socket_mode(pc->ring, recv_only_mode);
    if (pfring_enable_ring(pc->ring) != 0) {
        pfring_close(pc->ring);
        pc->ring = NULL;
        return DAQ_ERROR;
    }
    return DAQ_SUCCESS;
}

static unsigned pfring_daq_msg_receive(void *handle, const unsigned max_recv,
                                      const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat) 
{
    PfringContext *pc = (PfringContext *)handle;
    struct pfring_pkthdr hdr;
    u_char *pkt_data;
    unsigned count = 0;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    while (count < max_recv) 
    {
        if (pc->interrupted) {
            pc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }
        PfringPktDesc *desc = pc->pool.freelist;
        if (!desc) {
            *rstat = DAQ_RSTAT_NOBUF;
            break;
        }
        int rc = pfring_recv(pc->ring, &pkt_data, 0, &hdr, 0); 
        if (rc == 1) {
            uint32_t copy_len = (hdr.caplen > pc->snaplen) ? pc->snaplen : hdr.caplen;
            memcpy(desc->data, pkt_data, copy_len);
            desc->pkthdr.ts = hdr.ts;
            desc->pkthdr.pktlen = hdr.len;
            desc->msg.data_len = copy_len;

            pc->pool.freelist = desc->next;
            desc->next = NULL;
            
            msgs[count++] = &desc->msg;
            pc->stats.packets_received++;
            pc->pool.info.available--;
            
        } else if (rc == 0) {
            if (count == 0) 
                status = DAQ_RSTAT_TIMEOUT;
            break;
        } else {
            status = DAQ_RSTAT_ERROR;
            break;
        }
    }
    *rstat = status;
    return count;
}

static int pfring_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    PfringContext *pc = (PfringContext *)handle;
    PfringPktDesc *desc = (PfringPktDesc *)msg->priv;

    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;

    pc->stats.verdicts[verdict]++;

    if (pc->mode == DAQ_MODE_INLINE && verdict == DAQ_VERDICT_PASS) {
        int send_mode = pc->use_fast_tx ? -1 : 0;
        if (pfring_send(pc->ring, desc->data, desc->msg.data_len, send_mode) < 0) {
            pc->stats.hw_packets_dropped++;
        } else {
            pc->stats.packets_injected++;
        }
    }
    desc->next = pc->pool.freelist;
    pc->pool.freelist = desc;
    pc->pool.info.available++;
    return DAQ_SUCCESS;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    PfringContext *pc = (PfringContext *)handle;
    *stats = pc->stats;
    pfring_stats(pc->ring, &pc->hw_stats);
    stats->hw_packets_received = pc->hw_stats.recv;
    stats->hw_packets_dropped = pc->hw_stats.drop;
    return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (pc->ring) {
        pfring_close(pc->ring);
        pc->ring = NULL;
    }
    return DAQ_SUCCESS;
}

static void pfring_daq_interrupt(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    pc->interrupted = true;
}

static void pfring_daq_destroy(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return;
    }
    pfring_daq_stop(handle);
    if (pc->device) {
        free(pc->device);
    }
    if (pc->pool.pool) {
        for (unsigned i = 0; i < pc->pool.info.size; i++) {
            free(pc->pool.pool[i].data);
        }
        free(pc->pool.pool);
    }
    free(pc);
}

static int pfring_daq_get_datalink_type(void *handle) {
    return DLT_EN10MB;
}

static uint32_t pfring_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BPF | DAQ_CAPA_INTERRUPT | DAQ_CAPA_INJECT;
}

static int pfring_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info) {
    if (!handle || !info)
        return DAQ_ERROR_INVAL;
    PfringContext *pc = (PfringContext *)handle;
    *info = pc->pool.info;
    return DAQ_SUCCESS;
}

static int pfring_daq_set_filter(void *handle, const char *filter) {
    PfringContext *pc = (PfringContext *)handle;
    struct bpf_program fcode;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_compile_nopcap(pc->snaplen, DLT_EN10MB, &fcode,
                            filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        daq_base_api.set_errbuf(pc->modinst, "BPF compilation failed");
        return DAQ_ERROR;
    }
    if (pfring_set_bpf_filter(pc->ring, &fcode) < 0) {
        pcap_freecode(&fcode);
        daq_base_api.set_errbuf(pc->modinst, "Failed to set BPF filter");
        return DAQ_ERROR;
    }
    pcap_freecode(&fcode);
    return DAQ_SUCCESS;
}

static DAQ_VariableDesc_t pfring_variable_descs[] = {
    { "no_promisc", "Disable promiscuous mode", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "cluster_id", "PF_RING cluster ID", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "cluster_mode", "Cluster mode (2,4,5,6)", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "watermark", "Poll watermark", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "fast_tx", "Enable fast TX mode", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { NULL, NULL, 0 }
};

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t pfring_daq_module_data =
#endif
{
    .api_version = DAQ_MODULE_API_VERSION,
    .api_size = sizeof(DAQ_ModuleAPI_t),
    .module_version = DAQ_PFRING_VERSION,
    .name = "redborder_pfring",
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .load = pfring_daq_module_load,
    .interrupt = pfring_daq_interrupt,
    .unload = NULL,
    .get_variable_descs = NULL,
    .instantiate = pfring_daq_instantiate,
    .destroy = pfring_daq_destroy,
    .start = pfring_daq_start,
    .stop = pfring_daq_stop,
    .set_filter = pfring_daq_set_filter,
    .ioctl = NULL,
    .get_stats = pfring_daq_get_stats,
    .reset_stats = NULL,
    .get_snaplen = NULL,
    .get_capabilities = NULL,
    .get_datalink_type = pfring_daq_get_datalink_type,
    .config_load = NULL,
    .config_swap = NULL,
    .config_free = NULL,
    .msg_receive = pfring_daq_msg_receive,
    .msg_finalize = pfring_daq_msg_finalize,
    .get_msg_pool_info = pfring_daq_get_msg_pool_info,
};