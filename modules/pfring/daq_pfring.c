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
#include <poll.h>

#include <pfring.h>
#include <net/ethernet.h>

#include "daq_module_api.h"
#include <pfring.h>

#define DAQ_PFRING_VERSION 1
#define PF_RING_CLUSTER_ID 0
#define DEFAULT_POOL_SIZE 32
#define MAX_DEVICE_PAIRS 16
#define MAX_DEVICE_NAME_LEN 16

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
    char name[MAX_DEVICE_NAME_LEN];
    int index;
    pfring *ring;
    bool active;
    int peer_index;
} PfringDevice;

typedef struct {
    char *device;
    unsigned snaplen;
    int promisc;
    int buffer_size;
    DAQ_Mode mode;
    
    PfringDevice devices[MAX_DEVICE_PAIRS * 2];
    uint32_t device_count;
    uint32_t pair_count;
    
    uint32_t cluster_id;
    uint32_t cluster_type;
    
    DAQ_ModuleInstance_h modinst;
    DAQ_Stats_t stats;
    PfringMsgPool pool;
    volatile bool interrupted;

    int watermark;
    u_int8_t use_fast_tx;
    pfring_stat hw_stats;

    int curr_device_index;
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
static int add_device(PfringContext *pc, const char *device_name);
static int create_bridge(PfringContext *pc, const int *device_indices, size_t num_devices);
static int validate_interface_config(PfringContext *pc);

static DAQ_BaseAPI_t daq_base_api;

static int create_packet_pool(PfringContext *pc, unsigned size) {
    PfringMsgPool *pool = &pc->pool;
    memset(pool, 0, sizeof(PfringMsgPool));
    
    size = size * 4;
    
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
        desc->next = NULL;

        desc->next = pool->freelist;
        pool->freelist = desc;
    }
    
    return DAQ_SUCCESS;
}

static void destroy_packet_pool(PfringContext *pc) {
    PfringMsgPool *pool = &pc->pool;
    if (pool->pool) {
        for (unsigned i = 0; i < pool->info.size; i++) {
            PfringPktDesc *desc = &pool->pool[i];
            if (desc->next == NULL) {
                desc->next = pool->freelist;
                pool->freelist = desc;
            }
        }
        
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

static int add_device(PfringContext *pc, const char *device_name) {
    if (pc->device_count >= MAX_DEVICE_PAIRS * 2) {
        return DAQ_ERROR;
    }

    if (strncmp(device_name, "zc:", 3) == 0) {
        daq_base_api.set_errbuf(pc->modinst, "ZC is not supported by daq_pfring. Please use daq_pfring_zc");
        return DAQ_ERROR;
    }

    PfringDevice *dev = &pc->devices[pc->device_count];
    strncpy(dev->name, device_name, MAX_DEVICE_NAME_LEN - 1);
    dev->name[MAX_DEVICE_NAME_LEN - 1] = '\0';
    
    uint32_t flags = PF_RING_LONG_HEADER;
    if (pc->promisc) {
        flags |= PF_RING_PROMISC;
    }
    if (pc->use_fast_tx) {
        flags |= PF_RING_RX_PACKET_BOUNCE;
    }
    
    dev->ring = pfring_open(device_name, pc->snaplen, flags);
    if (!dev->ring) {
        daq_base_api.set_errbuf(pc->modinst, "pfring_open(): unable to open device '%s'", device_name);
        return DAQ_ERROR;
    }

    dev->index = pc->device_count;
    dev->active = false;
    dev->peer_index = -1;
    
    pc->device_count++;
    return DAQ_SUCCESS;
}

static int create_bridge(PfringContext *pc, const int *device_indices, size_t num_devices) {
    if (!pc || !device_indices || num_devices < 2) {
        return DAQ_ERROR;
    }

    for (size_t i = 0; i < num_devices; i++) {
        if (device_indices[i] < 0 || device_indices[i] >= pc->device_count) {
            return DAQ_ERROR;
        }
    }

    for (size_t i = 0; i < num_devices; i++) {
        if (pc->devices[device_indices[i]].peer_index != -1) {
            return DAQ_ERROR;
        }
    }

    for (size_t i = 0; i < num_devices; i++) {
        if (!pc->devices[device_indices[i]].active) {
            return DAQ_ERROR;
        }
    }

    for (size_t i = 0; i < num_devices; i++) {
        int next_index = (i + 1) % num_devices;
        pc->devices[device_indices[i]].peer_index = device_indices[next_index];
    }
    
    pc->pair_count++;
    
    return DAQ_SUCCESS;
}

static int validate_interface_config(PfringContext *pc) {
    if (pc->device_count == 0) {
        return DAQ_ERROR;
    }

    if (pc->mode == DAQ_MODE_INLINE) {
        if (pc->device_count % 2 != 0) {
            return DAQ_ERROR;
        }
        for (uint32_t i = 0; i < pc->device_count; i++) {
            if (pc->devices[i].peer_index == -1) {
                return DAQ_ERROR;
            }
        }
    }
    else if (pc->mode == DAQ_MODE_PASSIVE) {
        if (pc->device_count == 0) {
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
    int ret;

    pc = calloc(1, sizeof(PfringContext));
    if (!pc) {
        daq_base_api.set_errbuf(modinst, "Failed to allocate context");
        return DAQ_ERROR_NOMEM;
    }

    pc->modinst = modinst;
    pc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    pc->mode = daq_base_api.config_get_mode(modcfg);
    pc->promisc = PF_RING_PROMISC;
    pc->cluster_id = PF_RING_CLUSTER_ID;
    pc->cluster_type = 0;
    pc->watermark = 0;
    pc->use_fast_tx = 0;
    pc->device_count = 0;
    pc->pair_count = 0;
    pc->curr_device_index = 0;
    pc->interrupted = false;

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

    dev_ptr = pc->device;
    int current_pair[MAX_DEVICE_PAIRS];
    int pair_count = 0;

    while (*dev_ptr) {
        ret = parse_interface_name(dev_ptr, intf, sizeof(intf), &consumed);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to parse interface name");
            free(pc);
            return DAQ_ERROR;
        }

        ret = add_device(pc, intf);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to add interface");
            free(pc);
            return DAQ_ERROR;
        }

        current_pair[pair_count++] = pc->device_count - 1;

        dev_ptr += consumed;
        if (*dev_ptr == ':') {
            dev_ptr++;
            if (pc->mode == DAQ_MODE_INLINE && pair_count >= 2) {
                ret = create_bridge(pc, current_pair, pair_count);
                if (ret != DAQ_SUCCESS) {
                    daq_base_api.set_errbuf(modinst, "Failed to create bridge between interfaces");
                    free(pc);
                    return DAQ_ERROR;
                }
                pair_count = 0;
            }
        }
    }

    /* Handle any remaining devices in the last pair */
    if (pc->mode == DAQ_MODE_INLINE && pair_count >= 2) {
        ret = create_bridge(pc, current_pair, pair_count);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to create bridge between interfaces");
            free(pc);
            return DAQ_ERROR;
        }
    }

    if (validate_interface_config(pc) != DAQ_SUCCESS) {
        daq_base_api.set_errbuf(modinst, "Invalid interface configuration");
        free(pc);
        return DAQ_ERROR;
    }

    ret = create_packet_pool(pc, DEFAULT_POOL_SIZE);
    if (ret != DAQ_SUCCESS) {
        daq_base_api.set_errbuf(modinst, "Failed to create packet pool");
        free(pc);
        return ret;
    }

    *ctxt_ptr = pc;
    return DAQ_SUCCESS;
}

static int pfring_daq_start(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return DAQ_ERROR;
    }

    for (uint32_t i = 0; i < pc->device_count; i++) {
        PfringDevice *device = &pc->devices[i];
        
        if (pc->cluster_id > 0) {
            char app_name[32];
            snprintf(app_name, sizeof(app_name), "snort-cluster-%d-socket-%d", 
                    pc->cluster_id, i);
            pfring_set_application_name(device->ring, app_name);
            
            if (pfring_set_cluster(device->ring, pc->cluster_id, pc->cluster_type) != 0) {
                daq_base_api.set_errbuf(pc->modinst, "pfring_set_cluster failed for device '%s'", device->name);
                return DAQ_ERROR;
            }
        } else {
            char app_name[32];
            snprintf(app_name, sizeof(app_name), "snort-socket-%d", i);
            pfring_set_application_name(device->ring, app_name);
        }

        pfring_set_poll_watermark(device->ring, pc->watermark);

        if (pc->mode == DAQ_MODE_PASSIVE) {
            pfring_set_socket_mode(device->ring, recv_only_mode);
        }

        pfring_set_filtering_mode(device->ring, software_only);

        if (pc->mode == DAQ_MODE_INLINE) {
            pfring_set_direction(device->ring, rx_only_direction);
        } else if (pc->mode == DAQ_MODE_PASSIVE) {
            pfring_set_direction(device->ring, rx_and_tx_direction);
        }
    }

    for (uint32_t i = 0; i < pc->device_count; i++) {
        PfringDevice *device = &pc->devices[i];
        
        if (pfring_enable_ring(device->ring) != 0) {
            daq_base_api.set_errbuf(pc->modinst, "Failed to enable ring for device '%s'", device->name);
            for (uint32_t j = 0; j < i; j++) {
                pfring_disable_ring(pc->devices[j].ring);
            }
            return DAQ_ERROR;
        }
        
        device->active = true;
    }

    /* Reset statistics */
    memset(&pc->stats, 0, sizeof(DAQ_Stats_t));
    
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
    struct pollfd pfd[MAX_DEVICE_PAIRS * 2];
    
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

        PfringDevice *device = &pc->devices[pc->curr_device_index];
        int rc = pfring_recv(device->ring, &pkt_data, 0, &hdr, 0);
        
        if (rc == 0) {
            /* No packet to read: let's poll */
            for (uint32_t i = 0; i < pc->device_count; i++) {
                pfd[i].fd = pfring_get_selectable_fd(pc->devices[i].ring);
                pfd[i].events = POLLIN;
                pfd[i].revents = 0;
            }

            int poll_rc = poll(pfd, pc->device_count, 1000);
            if (poll_rc < 0) {
                if (errno == EINTR) {
                    status = DAQ_RSTAT_INTERRUPTED;
                    break;
                }
                daq_base_api.set_errbuf(pc->modinst, "Poll failed");
                status = DAQ_RSTAT_ERROR;
                break;
            }
            if (poll_rc == 0) {
                status = DAQ_RSTAT_TIMEOUT;
                break;
            }

            /* Try to receive from all devices after poll */
            uint32_t start_index = pc->curr_device_index;
            do {
                pc->curr_device_index = (pc->curr_device_index + 1) % pc->device_count;
                if (pc->curr_device_index == start_index) {
                    break;
                }
                device = &pc->devices[pc->curr_device_index];
                rc = pfring_recv(device->ring, &pkt_data, 0, &hdr, 0);
            } while (rc == 0);
        }
        
        if (rc == 1) {
            uint32_t copy_len = (hdr.caplen > pc->snaplen) ? pc->snaplen : hdr.caplen;
            memcpy(desc->data, pkt_data, copy_len);
            
            desc->pkthdr.ts = hdr.ts;
            desc->pkthdr.pktlen = hdr.len;
            desc->pkthdr.ingress_index = pc->curr_device_index;
            desc->pkthdr.egress_index = -1;
            desc->pkthdr.ingress_group = -1;
            desc->pkthdr.egress_group = -1;
            desc->pkthdr.flags = 0;
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
        PfringDevice *device = &pc->devices[pc->curr_device_index];
        if (device->peer_index >= 0) {
            int send_mode = pc->use_fast_tx ? -1 : 0;
            if (pfring_send(pc->devices[device->peer_index].ring, desc->data, desc->msg.data_len, send_mode) < 0) {
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

static int pfring_daq_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    PfringContext *pc = (PfringContext *)handle;

    /* Only supports GET_DEVICE_INDEX for now */
    if (cmd != DIOCTL_GET_DEVICE_INDEX || arglen != sizeof(DIOCTL_QueryDeviceIndex))
        return DAQ_ERROR_NOTSUP;

    DIOCTL_QueryDeviceIndex *qdi = (DIOCTL_QueryDeviceIndex *)arg;

    if (!qdi->device)
    {
        daq_base_api.set_errbuf(pc->modinst, "No device name to find the index of!");
        return DAQ_ERROR_INVAL;
    }

    for (uint32_t i = 0; i < pc->device_count; i++)
    {
        if (!strcmp(qdi->device, pc->devices[i].name))
        {
            qdi->index = pc->devices[i].index;
            return DAQ_SUCCESS;
        }
    }

    return DAQ_ERROR_NODEV;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    PfringContext *pc = (PfringContext *)handle;
    *stats = pc->stats;
    pfring_stats(pc->devices[0].ring, &pc->hw_stats);
    stats->hw_packets_received = pc->hw_stats.recv;
    stats->hw_packets_dropped = pc->hw_stats.drop;
    return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return DAQ_ERROR;
    }
    
    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].active) {
            pc->devices[i].active = false;
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
    
    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].ring) {
            pfring_close(pc->devices[i].ring);
            pc->devices[i].ring = NULL;
        }
    }
    
    destroy_packet_pool(pc);
    free(pc);
}

static int pfring_daq_get_datalink_type(void *handle) {
    return DLT_EN10MB;
}

static uint32_t pfring_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BPF | DAQ_CAPA_INTERRUPT | DAQ_CAPA_INJECT | DAQ_CAPA_REPLACE |
           DAQ_CAPA_UNPRIV_START | DAQ_CAPA_DEVICE_INDEX | DAQ_CAPA_BLOCK |
           DAQ_CAPA_WHITELIST | DAQ_CAPA_BLACKLIST;
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
    if (pfring_set_bpf_filter(pc->devices[0].ring, &fcode) < 0) {
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

static int pfring_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = pfring_variable_descs;

    return sizeof(pfring_variable_descs) / sizeof(DAQ_VariableDesc_t);
}

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

    instance->index = pc->device_count;
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

static void pfring_daq_reset_stats(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    pfring_stat ps;

    memset(&pc->stats, 0, sizeof(DAQ_Stats_t));
    memset(&ps, 0, sizeof(pfring_stat));

    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].ring) {
            pfring_stats(pc->devices[i].ring, &ps);
        }
    }
}

static int pfring_daq_get_snaplen(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    
    if (!pc) {
        return DAQ_ERROR;
    }
    
    return pc->snaplen;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static int pfring_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    PfringContext *pc = (PfringContext *)handle;

    if (type != DAQ_MSG_TYPE_PACKET)
        return DAQ_ERROR_NOTSUP;

    const DAQ_PktHdr_t *pkthdr = (const DAQ_PktHdr_t *)hdr;
    if (pkthdr->ingress_index >= pc->device_count)
        return DAQ_ERROR;

    PfringDevice *device = &pc->devices[pkthdr->ingress_index];
    int send_mode = pc->use_fast_tx ? -1 : 0;

    if (pfring_send(device->ring, data, data_len, send_mode) < 0) {
        pc->stats.hw_packets_dropped++;
        return DAQ_ERROR;
    }

    pc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int unload(void *handle) {
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int pfring_daq_inject_relative(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    PfringContext *pc = (PfringContext *)handle;
    PfringPktDesc *desc = (PfringPktDesc *)msg->priv;
    PfringDevice *device = &pc->devices[pc->curr_device_index];
    PfringDevice *target_device = reverse ? device : &pc->devices[device->peer_index];

    if (target_device->peer_index < 0)
        return DAQ_ERROR;

    int send_mode = pc->use_fast_tx ? -1 : 0;
    if (pfring_send(target_device->ring, data, data_len, send_mode) < 0) {
        pc->stats.hw_packets_dropped++;
        return DAQ_ERROR;
    }

    pc->stats.packets_injected++;
    return DAQ_SUCCESS;
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
    .name = "rb_pfring",
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE | DAQ_MODE_INLINE,
    .load = pfring_daq_module_load,
    .interrupt = pfring_daq_interrupt,
    .unload = unload,
    .get_variable_descs = pfring_daq_get_variable_descs,
    .instantiate = pfring_daq_instantiate,
    .destroy = pfring_daq_destroy,
    .start = pfring_daq_start,
    .stop = pfring_daq_stop,
    .set_filter = pfring_daq_set_filter,
    .ioctl = pfring_daq_ioctl,
    .get_stats = pfring_daq_get_stats,
    .reset_stats = pfring_daq_reset_stats,
    .get_snaplen = pfring_daq_get_snaplen,
    .get_capabilities = pfring_daq_get_capabilities,
    .get_datalink_type = pfring_daq_get_datalink_type,
    .config_load = NULL,
    .config_swap = NULL,
    .config_free = NULL,
    .inject = pfring_daq_inject,
    .inject_relative = pfring_daq_inject_relative,
    .msg_receive = pfring_daq_msg_receive,
    .msg_finalize = pfring_daq_msg_finalize,
    .get_msg_pool_info = pfring_daq_get_msg_pool_info,
};