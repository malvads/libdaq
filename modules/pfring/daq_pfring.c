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
    pfring *peer_ring;  // For inline mode
    uint32_t cluster_id;
    uint32_t cluster_type;
    
    DAQ_ModuleInstance_h modinst;
    DAQ_Stats_t stats;
    PfringMsgPool pool;
    volatile bool interrupted;

    int watermark;
    u_int8_t use_fast_tx;
    pfring_stat hw_stats;

    // New fields for multiple device pairs
    struct _pfring_instance *instances;
    uint32_t intf_count;
    struct _pfring_instance *curr_instance;
} PfringContext;

typedef struct _pfring_instance {
    struct _pfring_instance *next;
    char *name;
    int index;
    struct _pfring_instance *peer;
    pfring *ring;
    bool active;
} PfringInstance;

/* Forward declarations */
static PfringInstance *create_instance(PfringContext *pc, const char *device);
static void destroy_instance(PfringInstance *instance);
static int parse_interface_name(const char *input, char *intf, size_t intf_size, size_t *consumed);
static int add_instance(PfringContext *pc, const char *intf);
static int validate_interface_config(PfringContext *pc, int num_intfs);

static DAQ_BaseAPI_t daq_base_api;

static int create_packet_pool(PfringContext *pc, unsigned size) {
    PfringMsgPool *pool = &pc->pool;
    memset(pool, 0, sizeof(PfringMsgPool));
    
    // Increase pool size to handle high packet volumes
    size = size * 4;  // Quadruple the pool size for better handling of high packet volumes
    
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
        desc->next = NULL;  // Initialize next pointer to NULL

        desc->next = pool->freelist;
        pool->freelist = desc;
    }
    
    return DAQ_SUCCESS;
}

static void destroy_packet_pool(PfringContext *pc) {
    PfringMsgPool *pool = &pc->pool;
    if (pool->pool) {
        // First, ensure all descriptors are in the free list
        for (unsigned i = 0; i < pool->info.size; i++) {
            PfringPktDesc *desc = &pool->pool[i];
            if (desc->next == NULL) {  // If not in free list
                desc->next = pool->freelist;
                pool->freelist = desc;
            }
        }
        
        // Now free all descriptors
        for (unsigned i = 0; i < pool->info.size; i++) {
            if (pool->pool[i].data) {
                free(pool->pool[i].data);
                pool->pool[i].data = NULL;
            }
        }
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int pfring_daq_module_load(const DAQ_BaseAPI_t *base_api) {
    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

static int create_bridge(PfringContext *pc, const char *device_name1, const char *device_name2) {
    PfringInstance *peer1 = NULL, *peer2 = NULL;
    for (PfringInstance *instance = pc->instances; instance; instance = instance->next) {
        if (!strcmp(instance->name, device_name1))
            peer1 = instance;
        else if (!strcmp(instance->name, device_name2))
            peer2 = instance;
    }

    if (!peer1 || !peer2) {
        return DAQ_ERROR_NODEV;
    }

    peer1->peer = peer2;
    peer2->peer = peer1;

    return DAQ_SUCCESS;
}

static int parse_interface_name(const char *input, char *intf, size_t intf_size, size_t *consumed) {
    size_t len = strcspn(input, ":");
    
    if (len >= intf_size) {
        return DAQ_ERROR;
    }
    
    if (len == 0) {
        *consumed = 1;
        return DAQ_ERROR;
    }
    
    snprintf(intf, len + 1, "%s", input);
    *consumed = len;
    return DAQ_SUCCESS;
}

static int add_instance(PfringContext *pc, const char *intf) {
    PfringInstance *instance = create_instance(pc, intf);
    if (!instance) {
        return DAQ_ERROR;
    }

    instance->next = pc->instances;
    pc->instances = instance;
    pc->intf_count++;
    
    return DAQ_SUCCESS;
}

static int validate_interface_config(PfringContext *pc, int num_intfs)
{
    if (!pc->instances) {
        return DAQ_ERROR;
    }

    if (pc->mode == DAQ_MODE_INLINE) {
        if (num_intfs != 2) {
            return DAQ_ERROR;
        }

        PfringInstance *instances[2] = {pc->instances, pc->instances->next};
        
        if (!instances[0] || !instances[1] || !instances[0]->name || !instances[1]->name) {
            return DAQ_ERROR;
        }
    }
    else if (pc->mode == DAQ_MODE_PASSIVE) {
        if (num_intfs < 1) {
            return DAQ_ERROR;
        }
    }

    return DAQ_SUCCESS;
}

static int pfring_daq_instantiate(const DAQ_ModuleConfig_h modcfg, 
                                 DAQ_ModuleInstance_h modinst,
                                 void **ctxt_ptr)
{
    PfringContext *pc;
    const char *dev_ptr;
    size_t consumed;
    char intf[IFNAMSIZ];
    int num_intfs = 0;
    int ret;

    pc = calloc(1, sizeof(PfringContext));
    if (!pc) {
        daq_base_api.set_errbuf(modinst, "Failed to allocate context");
        return DAQ_ERROR_NOMEM;
    }

    // Initialize context
    pc->modinst = modinst;
    pc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    pc->mode = daq_base_api.config_get_mode(modcfg);
    pc->promisc = PF_RING_PROMISC;
    pc->cluster_id = PF_RING_CLUSTER_ID;
    pc->cluster_type = 0;
    pc->watermark = 0;
    pc->use_fast_tx = 0;
    pc->intf_count = 0;
    pc->instances = NULL;
    pc->curr_instance = NULL;
    pc->interrupted = false;

    // Parse configuration parameters
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

    pc->device = strdup(daq_base_api.config_get_input(modcfg));
    if (!pc->device) {
        daq_base_api.set_errbuf(modinst, "Failed to allocate device string");
        free(pc);
        return DAQ_ERROR_NOMEM;
    }

    // Parse and add instances
    dev_ptr = pc->device;
    while (*dev_ptr) {
        ret = parse_interface_name(dev_ptr, intf, sizeof(intf), &consumed);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to parse interface name");
            free(pc);
            return DAQ_ERROR;
        }

        ret = add_instance(pc, intf);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to add interface");
            free(pc);
            return DAQ_ERROR;
        }

        num_intfs++;
        dev_ptr += consumed;
        if (*dev_ptr == ':') dev_ptr++; // Skip the colon separator
    }

    // First validate the interface configuration
    if (validate_interface_config(pc, num_intfs) != DAQ_SUCCESS) {
        daq_base_api.set_errbuf(modinst, "Invalid interface configuration");
        free(pc);
        return DAQ_ERROR;
    }

    // Then create bridges if in inline mode
    if (pc->mode == DAQ_MODE_INLINE) {
        PfringInstance *instances[2] = {pc->instances, pc->instances->next};
        if (create_bridge(pc, instances[0]->name, instances[1]->name) != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to create bridge between interfaces");
            free(pc);
            return DAQ_ERROR;
        }
    }

    // Create packet pool
    ret = create_packet_pool(pc, DEFAULT_POOL_SIZE);
    if (ret != DAQ_SUCCESS) {
        daq_base_api.set_errbuf(modinst, "Failed to create packet pool");
        free(pc);
        return ret;
    }

    pc->curr_instance = pc->instances;
    *ctxt_ptr = pc;
    return DAQ_SUCCESS;
}

static int pfring_daq_start(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return DAQ_ERROR;
    }
    
    for (PfringInstance *instance = pc->instances; instance; instance = instance->next) {
        pfring_set_cluster(instance->ring, pc->cluster_id, pc->cluster_type);
        pfring_set_poll_watermark(instance->ring, pc->watermark);
        pfring_set_application_name(instance->ring, "daq_pfring");
        pfring_set_socket_mode(instance->ring, recv_only_mode);

        if (pfring_enable_ring(instance->ring) != 0) {
            return DAQ_ERROR;
        }
        
        instance->active = true;
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
            if (pc->stats.packets_outstanding > 0) {
                status = DAQ_RSTAT_NOBUF;
                break;
            }
            daq_base_api.set_errbuf(pc->modinst, "No packet descriptors available");
            status = DAQ_RSTAT_ERROR;
            break;
        }

        PfringInstance *instance = pc->curr_instance;
        int rc = pfring_recv(instance->ring, &pkt_data, 0, &hdr, 0);
        
        if (rc == 0) {
            PfringInstance *start = instance;
            do {
                instance = instance->next ? instance->next : pc->instances;
                if (instance != start) {
                    rc = pfring_recv(instance->ring, &pkt_data, 0, &hdr, 0);
                    if (rc == 1) {
                        pc->curr_instance = instance;
                        break;
                    }
                }
            } while (instance != start);
        }
        
        if (rc == 1) {
            uint32_t copy_len = (hdr.caplen > pc->snaplen) ? pc->snaplen : hdr.caplen;
            memcpy(desc->data, pkt_data, copy_len);
            
            desc->pkthdr.ts = hdr.ts;
            desc->pkthdr.pktlen = hdr.len;
            desc->msg.data_len = copy_len;
            desc->msg.priv = desc;

            pc->pool.freelist = desc->next;
            desc->next = NULL;
            
            msgs[count++] = &desc->msg;
            
            pc->stats.packets_received++;
            pc->stats.packets_outstanding++;
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
    pc->stats.packets_outstanding--;

    if (pc->mode == DAQ_MODE_INLINE && verdict == DAQ_VERDICT_PASS) {
        PfringInstance *instance = pc->curr_instance;
        if (instance && instance->peer) {
            int send_mode = pc->use_fast_tx ? -1 : 0;
            if (pfring_send(instance->peer->ring, desc->data, desc->msg.data_len, send_mode) < 0) {
                pc->stats.hw_packets_dropped++;
            } else {
                pc->stats.packets_injected++;
            }
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
    if (!pc) {
        return DAQ_ERROR;
    }
    
    for (PfringInstance *instance = pc->instances; instance; instance = instance->next) {
        if (instance->active) {
            instance->active = false;
        }
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
    
    while (pc->instances) {
        PfringInstance *instance = pc->instances;
        pc->instances = instance->next;
        destroy_instance(instance);
    }
    
    destroy_packet_pool(pc);
    free(pc);
}

static int pfring_daq_get_datalink_type(void *handle) {
    return DLT_EN10MB;
}

static uint32_t pfring_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BPF | DAQ_CAPA_INTERRUPT | DAQ_CAPA_INJECT | DAQ_CAPA_REPLACE;
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

static PfringInstance *create_instance(PfringContext *pc, const char *device) {
    PfringInstance *instance = calloc(1, sizeof(PfringInstance));
    if (!instance) {
        daq_base_api.set_errbuf(pc->modinst, "Failed to allocate memory for instance");
        return NULL;
    }

    instance->name = strdup(device);
    if (!instance->name) {
        free(instance);
        daq_base_api.set_errbuf(pc->modinst, "Failed to allocate memory for device name");
        return NULL;
    }

    instance->ring = pfring_open(device, pc->snaplen, pc->promisc);
    if (!instance->ring) {
        free(instance->name);
        free(instance);
        daq_base_api.set_errbuf(pc->modinst, "Failed to open device");
        return NULL;
    }

    instance->index = pc->intf_count;
    instance->active = false;
    instance->next = NULL;
    instance->peer = NULL;

    return instance;
}

static void destroy_instance(PfringInstance *instance) {
    if (instance) {
        if (instance->ring) {
            pfring_close(instance->ring);
            instance->ring = NULL;
        }
        if (instance->name) {
            free(instance->name);
            instance->name = NULL;
        }
        free(instance);
    }
}

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
    .get_capabilities = pfring_daq_get_capabilities,
    .get_datalink_type = pfring_daq_get_datalink_type,
    .config_load = NULL,
    .config_swap = NULL,
    .config_free = NULL,
    .msg_receive = pfring_daq_msg_receive,
    .msg_finalize = pfring_daq_msg_finalize,
    .get_msg_pool_info = pfring_daq_get_msg_pool_info,
};
