// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.

error_t
dto_create_doorbell(struct vdevice_node *node, dto_t *dto, uint32_t *phandle);

error_t
dto_create_msg_queue(struct vdevice_node *node, dto_t *dto);

error_t
dto_create_shm(struct vdevice_node *node, dto_t *dto, vmid_t self);

error_t
dto_create_msg_queue_pair(struct vdevice_node *node, dto_t *dto);
