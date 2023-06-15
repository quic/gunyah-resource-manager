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

error_t
dto_create_watchdog(struct vdevice_node *node, dto_t *dto);

error_t
dto_create_virtio_mmio(struct vdevice_node *node, dto_t *dto, vmid_t self);

error_t
dto_create_vrtc(struct vdevice_node *node, dto_t *dto);

error_t
patch_smmu_v2_nodes(const void *base_dtb, dto_t *dto, vmid_t vmid);

error_t
dto_guid_to_string(uint8_t *guid, size_t guid_len, char *output,
		   size_t output_len);

error_t
add_compatibles(struct vdevice_node *node, char *compatibles[],
		count_t compatible_cnt, dto_t *dto);
