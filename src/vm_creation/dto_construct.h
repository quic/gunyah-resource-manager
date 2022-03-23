// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

error_t
dto_create_doorbell(struct vdevice_node *node, dto_t *dto, uint32_t *phandle);

error_t
dto_create_msg_queue(struct vdevice_node *node, dto_t *dto);

error_t
dto_create_shm(struct vdevice_node *node, dto_t *dto, vmid_t self);

error_t
dto_create_msg_queue_pair(struct vdevice_node *node, dto_t *dto);

// Construct modification path node.
// This call constructs a overlay fragment at root '/', and then constructs
// the path nodes one by one.
// The call of dto_construct_begin_path/dto_construct_end_path cannot be nested.
error_t
dto_construct_begin_path(dto_t *dto, const char *path);

// Each path in relative_path is a device tree node. This call ends the node
// and exit the modification.
error_t
dto_construct_end_path(dto_t *dto, const char *path);

error_t
dto_guid_to_string(uint8_t *guid, size_t guid_len, char *output,
		   size_t output_len);
