// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SRC_DTO_CONSTRUCT_H_
#define SRC_DTO_CONSTRUCT_H_

error_t
dto_create_doorbell(const struct vdevice_node *node, dto_t *dto,
		    uint32_t *phandle);

error_t
dto_create_msg_queue(const struct vdevice_node *node, dto_t *dto);

error_t
dto_create_shm(const struct vdevice_node *node, dto_t *dto, vmid_t self);

error_t
dto_create_msg_queue_pair(const struct vdevice_node *node, dto_t *dto);

error_t
dto_create_watchdog(const struct vdevice_node *node, dto_t *dto);

error_t
dto_create_virtio_mmio(const void *base_dtb, const struct vdevice_node *node,
		       dto_t *dto, vmid_t self);

error_t
dto_create_pci(const void *base_dtb, const struct vdevice_node *node,
	       dto_t *dto, vmid_t vmid);

error_t
dto_create_vrtc(const struct vdevice_node *node, dto_t *dto);

error_t
dto_guid_to_string(uint8_t *guid, size_t guid_len, char *output,
		   size_t output_len);

#else

#error src/vm_creation/dto_construct.h multiple include

#endif
