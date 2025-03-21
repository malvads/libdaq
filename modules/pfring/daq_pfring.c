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
    char *filter;
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
} PfringContext;

static DAQ_BaseAPI_t daq_base_api;

/*

    Malvads magic below

    !!!! EXPERIMENTAL MODULE !!!!!
*/
static int create_packet_pool(PfringContext *pc, unsigned size) {
    printf("\n=== Creating packet pool ===\n");
    printf("| Pool size: %u\n", size);
    printf("| Snaplen: %u\n", pc->snaplen);
    
    PfringMsgPool *pool = &pc->pool;
    memset(pool, 0, sizeof(PfringMsgPool));
    
    printf("| Allocating descriptor array...\n");
    pool->pool = calloc(size, sizeof(PfringPktDesc));
    if (!pool->pool) {
        printf("!!! ERROR: Failed to allocate %zu bytes for descriptors\n", 
              size * sizeof(PfringPktDesc));
        return DAQ_ERROR_NOMEM;
    }
    
    pool->info.size = size;
    pool->info.available = size;
    pool->info.mem_size = size * sizeof(PfringPktDesc);
    printf("| Initial pool info: size=%u, available=%u, mem_size=%zu\n",
          pool->info.size, pool->info.available, pool->info.mem_size);

    for (unsigned i = 0; i < size; i++) {
        PfringPktDesc *desc = &pool->pool[i];
        printf("| [Descriptor %u] Allocating data buffer...\n", i);
        desc->data = malloc(pc->snaplen);
        if (!desc->data) {
            printf("!!! ERROR: Failed to allocate %u bytes for data buffer %u\n",
                  pc->snaplen, i);
            printf("| Cleaning up %u previously allocated buffers...\n", i);
            while (i-- > 0) {
                printf("| Freeing buffer %u...\n", i);
                free(pool->pool[i].data);
            }
            printf("| Freeing descriptor array...\n");
            free(pool->pool);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += pc->snaplen;

        printf("| [Descriptor %u] Initializing message structure...\n", i);
        desc->msg.type = DAQ_MSG_TYPE_PACKET;
        desc->msg.hdr_len = sizeof(DAQ_PktHdr_t);
        desc->msg.hdr = &desc->pkthdr;
        desc->msg.data = desc->data;
        desc->msg.owner = pc->modinst;
        desc->msg.priv = desc;

        printf("| [Descriptor %u] Adding to free list...\n", i);
        desc->next = pool->freelist;
        pool->freelist = desc;
    }

    printf("=== Pool created successfully ===\n");
    printf("| Total descriptors: %u\n", pool->info.size);
    printf("| Total memory: %zu bytes\n", pool->info.mem_size);
    printf("| First free descriptor: %p\n", (void*)pool->freelist);
    return DAQ_SUCCESS;
}


static int pfring_daq_module_load(const DAQ_BaseAPI_t *base_api) {
    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

static int pfring_daq_instantiate(const DAQ_ModuleConfig_h modcfg, 
                                 DAQ_ModuleInstance_h modinst,
                                 void **ctxt_ptr) {
    printf("\n=== Instantiating module ===\n");
    
    printf("| Allocating context...\n");
    PfringContext *pc = calloc(1, sizeof(PfringContext));
    if (!pc) {
        printf("!!! ERROR: Failed to allocate %zu bytes for context\n",
              sizeof(PfringContext));
        return DAQ_ERROR_NOMEM;
    }
    
    pc->modinst = modinst;
    pc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    pc->promisc = PF_RING_PROMISC;
    pc->cluster_id = PF_RING_CLUSTER_ID;
    
    const char *input = daq_base_api.config_get_input(modcfg);
    printf("| Input device: %s\n", input);
    
    printf("| Duplicating device string...\n");
    pc->device = strdup(input);
    if (!pc->device) {
        printf("!!! ERROR: Failed to duplicate device string\n");
        printf("| Freeing context...\n");
        free(pc);
        return DAQ_ERROR_NOMEM;
    }
    
    printf("| Creating packet pool...\n");
    int rc = create_packet_pool(pc, DEFAULT_POOL_SIZE);
    if (rc != DAQ_SUCCESS) {
        printf("!!! ERROR: Packet pool creation failed\n");
        printf("| Cleaning up device string...\n");
        free(pc->device);
        printf("| Freeing context...\n");
        free(pc);
        return rc;
    }
    
    *ctxt_ptr = pc;
    printf("=== Instance created successfully ===\n");
    printf("| Context pointer: %p\n", pc);
    return DAQ_SUCCESS;
}



static int pfring_daq_start(void *handle) {
    printf("\n=== Starting module ===\n");
    PfringContext *pc = (PfringContext *)handle;
    
    if (!pc) {
        printf("!!! ERROR: Null context pointer!\n");
        return DAQ_ERROR;
    }
    
    printf("| Opening PF_RING on %s\n", pc->device);
    printf("| Snaplen: %u, Promisc: %d\n", pc->snaplen, pc->promisc);
    pc->ring = pfring_open(pc->device, pc->snaplen, pc->promisc);
    
    if (!pc->ring) {
        printf("!!! ERROR: pfring_open failed\n");
        printf("| Last error: %s\n");
        daq_base_api.set_errbuf(pc->modinst, "pfring_open failed");
        return DAQ_ERROR;
    }
    
    printf("| Configuring application name...\n");
    pfring_set_application_name(pc->ring, "daq_pfring");
    pfring_set_socket_mode(pc->ring, recv_only_mode);
    
    printf("| Setting cluster ID: %u, Type: %u\n", 
          pc->cluster_id, pc->cluster_type);
    pfring_set_cluster(pc->ring, pc->cluster_id, pc->cluster_type);
    
    printf("| Enabling ring...\n");
    if (pfring_enable_ring(pc->ring) != 0) {
        printf("!!! ERROR: Failed to enable ring\n");
        printf("| Last error: %s\n");
        printf("| Closing ring...\n");
        pfring_close(pc->ring);
        pc->ring = NULL;
        return DAQ_ERROR;
    }
    
    printf("=== Module started successfully ===\n");
    return DAQ_SUCCESS;
}
static unsigned pfring_daq_msg_receive(void *handle, const unsigned max_recv,
                                      const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat) {
    printf("\n=== Receiving messages ===\n");
    PfringContext *pc = (PfringContext *)handle;
    
    if (!pc || !pc->ring) {
        printf("!!! ERROR: Invalid context or ring not initialized\n");
        *rstat = DAQ_RSTAT_ERROR;
        return 0;
    }
    
    printf("| Max messages to receive: %u\n", max_recv);
    printf("| Current free descriptors: %u\n", pc->pool.info.available);
    
    unsigned count = 0;
    struct pfring_pkthdr hdr;
    u_char *pkt_data;
    
    while (count < max_recv) {
        printf("\n| Receive loop iteration: %u/%u\n", count+1, max_recv);
        
        if (pc->interrupted) {
            printf("!!! INTERRUPTED: Breaking receive loop\n");
            *rstat = DAQ_RSTAT_INTERRUPTED;
            pc->interrupted = false;
            break;
        }
        
        printf("| Calling pfring_recv...\n");
        int rc = pfring_recv(pc->ring, &pkt_data, 0, &hdr, 1);
        printf("| pfring_recv returned: %d\n", rc);
        
        if (rc == 1) {
            printf("| Received packet: len=%u, caplen=%u\n", hdr.len, hdr.caplen);
            printf("| Timestamp: %ld.%06ld\n", hdr.ts.tv_sec, hdr.ts.tv_usec);
            
            PfringPktDesc *desc = pc->pool.freelist;
            if (!desc) {
                printf("!!! NO BUFFERS: Free list empty\n");
                *rstat = DAQ_RSTAT_NOBUF;
                break;
            }
            
            printf("| Using descriptor: %p\n", desc);
            printf("| Copying %u bytes to buffer...\n", hdr.caplen);
            memcpy(desc->data, pkt_data, hdr.caplen);
            
            printf("| Updating headers...\n");
            desc->pkthdr.ts.tv_sec = hdr.ts.tv_sec;
            desc->pkthdr.ts.tv_usec = hdr.ts.tv_usec;
            desc->pkthdr.pktlen = hdr.len;
            desc->msg.data_len = hdr.caplen;
            
            printf("| Updating free list...\n");
            pc->pool.freelist = desc->next;
            desc->next = NULL;
            
            printf("| Adding message to result array\n");
            msgs[count++] = &desc->msg;
            pc->stats.packets_received++;
            pc->pool.info.available--;
            
            printf("| New available descriptors: %u\n", pc->pool.info.available);
        }
        else if (rc == 0) {
            printf("| Timeout occurred\n");
            *rstat = DAQ_RSTAT_TIMEOUT;
            break;
        }
        else {
            printf("!!! RECEIVE ERROR: %s\n");
            *rstat = DAQ_RSTAT_ERROR;
            break;
        }
    }
    
    printf("=== Returning %u messages ===\n", count);
    return count;
}

static int pfring_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, 
                                  DAQ_Verdict verdict) {
    PfringContext *pc = (PfringContext *)handle;
    PfringPktDesc *desc = (PfringPktDesc *)msg->priv;

    desc->next = pc->pool.freelist;
    pc->pool.freelist = desc;
    pc->stats.verdicts[verdict]++;
    
    return DAQ_SUCCESS;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    PfringContext *pc = (PfringContext *)handle;
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


static void pfring_daq_destroy(void *handle) {
    printf("\n=== Destroying module ===\n");
    PfringContext *pc = (PfringContext *)handle;
    
    if (!pc) {
        printf("!!! WARNING: Null context pointer\n");
        return;
    }
    
    printf("| Stopping module...\n");
    pfring_daq_stop(handle);
    
    if (pc->device) {
        printf("| Freeing device string: %s\n", pc->device);
        free(pc->device);
    }
    
    if (pc->pool.pool) {
        printf("| Cleaning up packet pool:\n");
        printf("  - Total descriptors: %u\n", pc->pool.info.size);
        
        for (unsigned i = 0; i < pc->pool.info.size; i++) {
            if (pc->pool.pool[i].data) {
                printf("  | Freeing data buffer %u...\n", i);
                free(pc->pool.pool[i].data);
            }
        }
        
        printf("| Freeing descriptor array...\n");
        free(pc->pool.pool);
    }
    
    printf("| Freeing context...\n");
    free(pc);
    printf("=== Destruction complete ===\n");
}


static int pfring_daq_get_datalink_type(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    return DLT_EN10MB;
}

static uint32_t pfring_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BPF | DAQ_CAPA_INTERRUPT | DAQ_CAPA_INJECT;
}

static int pfring_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info) {
    printf("\n=== Getting pool info ===\n");
    
    if (!handle || !info) {
        printf("!!! ERROR: Null handle (%p) or info (%p)\n", handle, info);
        return DAQ_ERROR_INVAL;
    }
    
    PfringContext *pc = (PfringContext *)handle;
    printf("| Context valid: %s\n", pc ? "yes" : "no");
    
    if (!pc->pool.pool) {
        printf("!!! ERROR: Pool not initialized\n");
        return DAQ_ERROR;
    }
    
    printf("| Current pool status:\n");
    printf("  - Total descriptors: %u\n", pc->pool.info.size);
    printf("  - Available descriptors: %u\n", pc->pool.info.available);
    printf("  - Memory used: %zu bytes\n", pc->pool.info.mem_size);
    
    *info = pc->pool.info;
    printf("=== Pool info retrieved ===\n");
    return DAQ_SUCCESS;
}


static DAQ_VariableDesc_t pfring_variable_descs[] = {
    { "cluster_id", "PF_RING cluster ID", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "no_promisc", "Disable promiscuous mode", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
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
    .unload = NULL,
    .get_variable_descs = NULL,
    .instantiate = pfring_daq_instantiate,
    .destroy = pfring_daq_destroy,
    .start = pfring_daq_start,
    .stop = pfring_daq_stop,
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