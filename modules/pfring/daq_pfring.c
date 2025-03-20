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
    pfring *ring;
    ring = pfring_open(NULL, 1500, PF_RING_PROMISC);
    if (!ring) {
        return DAQ_ERROR;
    }
    *ctxt_ptr = (void *)ring;
    return DAQ_SUCCESS;
}

static void pfring_daq_destroy(void *handle) {
    if (handle) {
        pfring_close((pfring *)handle);
    }
}

static int pfring_daq_set_filter(void *handle, const char *filter) {
    if (!handle || !filter) {
        return DAQ_ERROR;
    }
    if (pfring_set_bpf_filter((pfring *)handle, filter) != 0) {
        return DAQ_ERROR;
    }
    return DAQ_SUCCESS;
}

static int pfring_daq_start(void *handle)
{
  return NULL;
}

static int pfring_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
  return NULL;
}

static int pfring_daq_interrupt(void *handle)
{
    return NULL;
}

static int pfring_daq_stop(void *handle)
{
  return NULL;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
  return NULL;
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
  return NULL;
}

static unsigned pfring_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
  return NULL;
}

static int pfring_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    return NULL;
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
