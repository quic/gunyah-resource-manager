// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef struct gunyah_hyp_hypervisor_identify_result {
	hyp_api_info_t _Alignas(register_t) hyp_api_info;
	hyp_api_flags0_t _Alignas(register_t) api_flags_0;
	hyp_api_flags1_t _Alignas(register_t) api_flags_1;
	hyp_api_flags2_t _Alignas(register_t) api_flags_2;
} gunyah_hyp_hypervisor_identify_result_t;

gunyah_hyp_hypervisor_identify_result_t
gunyah_hyp_hypervisor_identify(void);

typedef struct gunyah_hyp_partition_create_partition_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_partition_result_t;

gunyah_hyp_partition_create_partition_result_t
gunyah_hyp_partition_create_partition(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_cspace_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_cspace_result_t;

gunyah_hyp_partition_create_cspace_result_t
gunyah_hyp_partition_create_cspace(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_addrspace_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_addrspace_result_t;

gunyah_hyp_partition_create_addrspace_result_t
gunyah_hyp_partition_create_addrspace(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_memextent_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_memextent_result_t;

gunyah_hyp_partition_create_memextent_result_t
gunyah_hyp_partition_create_memextent(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_thread_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_thread_result_t;

gunyah_hyp_partition_create_thread_result_t
gunyah_hyp_partition_create_thread(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_doorbell_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_doorbell_result_t;

gunyah_hyp_partition_create_doorbell_result_t
gunyah_hyp_partition_create_doorbell(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_msgqueue_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_msgqueue_result_t;

gunyah_hyp_partition_create_msgqueue_result_t
gunyah_hyp_partition_create_msgqueue(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_vic_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_vic_result_t;

gunyah_hyp_partition_create_vic_result_t
gunyah_hyp_partition_create_vic(cap_id_t src_partition, cap_id_t cspace);

typedef struct gunyah_hyp_partition_create_vpm_group_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_vpm_group_result_t;

gunyah_hyp_partition_create_vpm_group_result_t
gunyah_hyp_partition_create_vpm_group(cap_id_t src_partition, cap_id_t cspace);

error_t
gunyah_hyp_object_activate(cap_id_t cap);

error_t
gunyah_hyp_object_activate_from(cap_id_t cspace, cap_id_t cap);

error_t
gunyah_hyp_object_reset(cap_id_t cap);

error_t
gunyah_hyp_object_reset_from(cap_id_t cspace, cap_id_t cap);

error_t
gunyah_hyp_doorbell_bind_virq(cap_id_t doorbell, cap_id_t vic, virq_t virq);

error_t
gunyah_hyp_doorbell_unbind_virq(cap_id_t doorbell);

typedef struct gunyah_hyp_doorbell_send_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	uint64_t _Alignas(register_t) old_flags;
} gunyah_hyp_doorbell_send_result_t;

gunyah_hyp_doorbell_send_result_t
gunyah_hyp_doorbell_send(cap_id_t doorbell, uint64_t new_flags);

typedef struct gunyah_hyp_doorbell_receive_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	uint64_t _Alignas(register_t) old_flags;
} gunyah_hyp_doorbell_receive_result_t;

gunyah_hyp_doorbell_receive_result_t
gunyah_hyp_doorbell_receive(cap_id_t doorbell, uint64_t clear_flags);

error_t
gunyah_hyp_doorbell_reset(cap_id_t doorbell);

error_t
gunyah_hyp_doorbell_mask(cap_id_t doorbell, uint64_t enable_mask,
			 uint64_t ack_mask);

error_t
gunyah_hyp_msgqueue_bind_send_virq(cap_id_t msgqueue, cap_id_t vic,
				   virq_t virq);

error_t
gunyah_hyp_msgqueue_bind_receive_virq(cap_id_t msgqueue, cap_id_t vic,
				      virq_t virq);

error_t
gunyah_hyp_msgqueue_unbind_send_virq(cap_id_t msgqueue);

error_t
gunyah_hyp_msgqueue_unbind_receive_virq(cap_id_t msgqueue);

typedef struct gunyah_hyp_msgqueue_send_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	bool _Alignas(register_t) not_full;
	uint8_t _pad1[7]; // Pad for struct static zero initialization
} gunyah_hyp_msgqueue_send_result_t;

gunyah_hyp_msgqueue_send_result_t
gunyah_hyp_msgqueue_send(cap_id_t msgqueue, size_t size, user_ptr_t data,
			 msgqueue_send_flags_t send_flags);

typedef struct gunyah_hyp_msgqueue_receive_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	size_t _Alignas(register_t) size;
	bool _Alignas(register_t) not_empty;
	uint8_t _pad1[7]; // Pad for struct static zero initialization
} gunyah_hyp_msgqueue_receive_result_t;

gunyah_hyp_msgqueue_receive_result_t
gunyah_hyp_msgqueue_receive(cap_id_t msgqueue, user_ptr_t buffer,
			    size_t buf_size);

error_t
gunyah_hyp_msgqueue_flush(cap_id_t msgqueue);

error_t
gunyah_hyp_msgqueue_configure_send(cap_id_t msgqueue, count_t not_full_thres,
				   count_t not_full_holdoff);

error_t
gunyah_hyp_msgqueue_configure_receive(cap_id_t msgqueue,
				      count_t  not_empty_thres,
				      count_t  not_empty_holdoff);

error_t
gunyah_hyp_msgqueue_configure(cap_id_t		     msgqueue,
			      msgqueue_create_info_t create_info);

error_t
gunyah_hyp_cspace_delete_cap_from(cap_id_t cspace, cap_id_t cap);

typedef struct gunyah_hyp_cspace_copy_cap_from_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_cspace_copy_cap_from_result_t;

gunyah_hyp_cspace_copy_cap_from_result_t
gunyah_hyp_cspace_copy_cap_from(cap_id_t src_cspace, cap_id_t src_cap,
				cap_id_t dest_cspace, cap_rights_t rights_mask);

error_t
gunyah_hyp_cspace_revoke_cap_from(cap_id_t src_cspace, cap_id_t src_cap);

error_t
gunyah_hyp_cspace_configure(cap_id_t cspace, count_t max_caps);

error_t
gunyah_hyp_hwirq_bind_virq(cap_id_t hwirq, cap_id_t vic, virq_t virq);

error_t
gunyah_hyp_hwirq_unbind_virq(cap_id_t hwirq);

error_t
gunyah_hyp_vic_configure(cap_id_t vic, count_t max_vcpus, count_t max_virqs,
			 vic_option_flags_t vic_options, count_t max_msis);

error_t
gunyah_hyp_vic_attach_vcpu(cap_id_t vic, cap_id_t vcpu, index_t index);

error_t
gunyah_hyp_addrspace_attach_thread(cap_id_t addrspace, cap_id_t thread);

error_t
gunyah_hyp_addrspace_map(cap_id_t addrspace, cap_id_t memextent, vmaddr_t vbase,
			 memextent_mapping_attrs_t map_attrs,
			 addrspace_map_flags_t map_flags, size_t offset,
			 size_t size);

error_t
gunyah_hyp_addrspace_unmap(cap_id_t addrspace, cap_id_t memextent,
			   vmaddr_t vbase, addrspace_map_flags_t map_flags,
			   size_t offset, size_t size);

error_t
gunyah_hyp_addrspace_update_access(cap_id_t addrspace, cap_id_t memextent,
				   vmaddr_t		    vbase,
				   memextent_access_attrs_t access_attrs,
				   addrspace_map_flags_t    map_flags,
				   size_t offset, size_t size);

error_t
gunyah_hyp_addrspace_configure(cap_id_t addrspace, vmid_t vmid);

error_t
gunyah_hyp_addrspace_attach_vdma(cap_id_t addrspace, cap_id_t dma_device,
				 index_t index);

error_t
gunyah_hyp_memextent_modify(cap_id_t memextent, memextent_modify_flags_t flags,
			    size_t offset, size_t size);

error_t
gunyah_hyp_memextent_configure(cap_id_t memextent, paddr_t phys_base,
			       size_t size, memextent_attrs_t attributes);

error_t
gunyah_hyp_memextent_configure_derive(cap_id_t memextent,
				      cap_id_t parent_memextent, size_t offset,
				      size_t		size,
				      memextent_attrs_t attributes);

error_t
gunyah_hyp_vcpu_configure(cap_id_t cap_id, vcpu_option_flags_t vcpu_options);

error_t
gunyah_hyp_vcpu_poweron(cap_id_t cap_id, uint64_t entry_point, uint64_t context,
			vcpu_poweron_flags_t flags);

error_t
gunyah_hyp_vcpu_poweroff(cap_id_t cap_id, vcpu_poweroff_flags_t flags);

error_t
gunyah_hyp_vcpu_kill(cap_id_t cap_id);

error_t
gunyah_hyp_scheduler_yield(scheduler_yield_control_t control, uint64_t arg1);

error_t
gunyah_hyp_vpm_group_attach_vcpu(cap_id_t vpm_group, cap_id_t vcpu,
				 index_t index);

error_t
gunyah_hyp_vcpu_set_affinity(cap_id_t cap_id, cpu_index_t affinity);

error_t
gunyah_hyp_cspace_attach_thread(cap_id_t cspace, cap_id_t thread);

typedef struct gunyah_hyp_trace_update_class_flags_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	uint64_t _Alignas(register_t) flags;
} gunyah_hyp_trace_update_class_flags_result_t;

gunyah_hyp_trace_update_class_flags_result_t
gunyah_hyp_trace_update_class_flags(uint64_t set_flags, uint64_t clear_flags);

error_t
gunyah_hyp_vpm_group_bind_virq(cap_id_t vpm_group, cap_id_t vic, virq_t virq);

error_t
gunyah_hyp_vpm_group_unbind_virq(cap_id_t vpm_group);

typedef struct gunyah_hyp_vpm_group_get_state_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	uint64_t _Alignas(register_t) vpm_state;
} gunyah_hyp_vpm_group_get_state_result_t;

gunyah_hyp_vpm_group_get_state_result_t
gunyah_hyp_vpm_group_get_state(cap_id_t vpm_group);

error_t
gunyah_hyp_vcpu_set_priority(cap_id_t cap_id, priority_t priority);

error_t
gunyah_hyp_vcpu_set_timeslice(cap_id_t cap_id, nanoseconds_t timeslice);

typedef struct gunyah_hyp_partition_create_virtio_mmio_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	cap_id_t _Alignas(register_t) new_cap;
} gunyah_hyp_partition_create_virtio_mmio_result_t;

gunyah_hyp_partition_create_virtio_mmio_result_t
gunyah_hyp_partition_create_virtio_mmio(cap_id_t src_partition,
					cap_id_t cspace);

error_t
gunyah_hyp_virtio_mmio_configure(cap_id_t virtio_mmio, cap_id_t memextent,
				 count_t vqs_num, virtio_option_flags_t flags,
				 virtio_device_type_t device_type);

error_t
gunyah_hyp_virtio_mmio_backend_bind_virq(cap_id_t virtio_mmio, cap_id_t vic,
					 virq_t virq);

error_t
gunyah_hyp_virtio_mmio_backend_unbind_virq(cap_id_t virtio_mmio);

error_t
gunyah_hyp_virtio_mmio_frontend_bind_virq(cap_id_t virtio_mmio, cap_id_t vic,
					  virq_t virq);

error_t
gunyah_hyp_virtio_mmio_frontend_unbind_virq(cap_id_t virtio_mmio);

error_t
gunyah_hyp_virtio_mmio_backend_assert_virq(cap_id_t virtio_mmio,
					   uint32_t interrupt_status);

error_t
gunyah_hyp_virtio_mmio_backend_set_dev_features(cap_id_t virtio_mmio,
						uint32_t sel,
						uint32_t dev_feat);

error_t
gunyah_hyp_virtio_mmio_backend_set_queue_num_max(cap_id_t virtio_mmio,
						 uint32_t sel,
						 uint32_t queue_num_max);

typedef struct gunyah_hyp_virtio_mmio_backend_get_drv_features_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	uint32_t _Alignas(register_t) drv_feat;
	uint8_t _pad1[4]; // Pad for struct static zero initialization
} gunyah_hyp_virtio_mmio_backend_get_drv_features_result_t;

gunyah_hyp_virtio_mmio_backend_get_drv_features_result_t
gunyah_hyp_virtio_mmio_backend_get_drv_features(cap_id_t virtio_mmio,
						uint32_t sel);

typedef struct gunyah_hyp_virtio_mmio_backend_get_queue_info_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	uint32_t _Alignas(register_t) queue_num;
	uint8_t _pad1[4]; // Pad for struct static zero initialization
	uint32_t _Alignas(register_t) queue_ready;
	uint8_t _pad2[4]; // Pad for struct static zero initialization
	uint64_t _Alignas(register_t) queue_desc;
	uint64_t _Alignas(register_t) queue_drv;
	uint64_t _Alignas(register_t) queue_dev;
} gunyah_hyp_virtio_mmio_backend_get_queue_info_result_t;

gunyah_hyp_virtio_mmio_backend_get_queue_info_result_t
gunyah_hyp_virtio_mmio_backend_get_queue_info(cap_id_t virtio_mmio,
					      uint32_t sel);

typedef struct gunyah_hyp_virtio_mmio_backend_get_notification_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	register_t _Alignas(register_t) vqs_bitmap;
	virtio_mmio_notify_reason_t _Alignas(register_t) reason;
} gunyah_hyp_virtio_mmio_backend_get_notification_result_t;

gunyah_hyp_virtio_mmio_backend_get_notification_result_t
gunyah_hyp_virtio_mmio_backend_get_notification(cap_id_t virtio_mmio);

error_t
gunyah_hyp_virtio_mmio_backend_acknowledge_reset(cap_id_t virtio_mmio);

error_t
gunyah_hyp_virtio_mmio_backend_update_status(cap_id_t virtio_mmio,
					     uint32_t val);

error_t
gunyah_hyp_vic_bind_msi_source(cap_id_t vic, cap_id_t msi_source);

typedef struct gunyah_hyp_prng_get_entropy_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	uint32_t _Alignas(register_t) data0;
	uint8_t _pad1[4]; // Pad for struct static zero initialization
	uint32_t _Alignas(register_t) data1;
	uint8_t _pad2[4]; // Pad for struct static zero initialization
	uint32_t _Alignas(register_t) data2;
	uint8_t _pad3[4]; // Pad for struct static zero initialization
	uint32_t _Alignas(register_t) data3;
	uint8_t _pad4[4]; // Pad for struct static zero initialization
} gunyah_hyp_prng_get_entropy_result_t;

gunyah_hyp_prng_get_entropy_result_t
gunyah_hyp_prng_get_entropy(count_t num_bytes);

error_t
gunyah_hyp_cspace_revoke_caps_from(cap_id_t src_cspace, cap_id_t master_cap);

typedef struct gunyah_hyp_addrspace_lookup_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	size_t _Alignas(register_t) offset;
	size_t _Alignas(register_t) size;
	memextent_mapping_attrs_t _Alignas(register_t) map_attrs;
	uint8_t _pad1[4]; // Pad for struct static zero initialization
} gunyah_hyp_addrspace_lookup_result_t;

gunyah_hyp_addrspace_lookup_result_t
gunyah_hyp_addrspace_lookup(cap_id_t addrspace, cap_id_t memextent,
			    vmaddr_t vbase, size_t size);

error_t
gunyah_hyp_addrspace_configure_info_area(cap_id_t addrspace,
					 cap_id_t info_area_me, vmaddr_t ipa);

error_t
gunyah_hyp_vcpu_bind_virq(cap_id_t vcpu, cap_id_t vic, virq_t virq,
			  vcpu_virq_type_t virq_type);

error_t
gunyah_hyp_vcpu_unbind_virq(cap_id_t vcpu, vcpu_virq_type_t virq_type);

error_t
gunyah_hyp_virtio_input_configure(cap_id_t virtio_mmio_cap, uint64_t devids,
				  uint32_t prop_bits, uint32_t num_evtypes,
				  uint32_t num_absaxes);

error_t
gunyah_hyp_virtio_input_set_data(cap_id_t virtio_mmio_cap, uint32_t sel,
				 uint32_t subsel, uint32_t size, vmaddr_t data);

error_t
gunyah_hyp_addrspace_configure_vmmio(cap_id_t addrspace, vmaddr_t vbase,
				     size_t			    size,
				     addrspace_vmmio_configure_op_t op);

error_t
gunyah_hyp_memextent_donate(memextent_donate_options_t options, cap_id_t from,
			    cap_id_t to, size_t offset, size_t size);

error_t
gunyah_hyp_addrspace_attach_vdevice(cap_id_t addrspace, cap_id_t vdevice,
				    index_t index, vmaddr_t vbase, size_t size,
				    addrspace_attach_vdevice_flags_t flags);

error_t
gunyah_hyp_vcpu_register_write(cap_id_t vcpu, vcpu_register_set_t register_set,
			       index_t register_index, uint64_t value);

typedef struct gunyah_hyp_vcpu_run_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	vcpu_run_state_t _Alignas(register_t) vcpu_state;
	uint8_t _pad1[4]; // Pad for struct static zero initialization
	register_t _Alignas(register_t) state_data_0;
	register_t _Alignas(register_t) state_data_1;
	register_t _Alignas(register_t) state_data_2;
} gunyah_hyp_vcpu_run_result_t;

gunyah_hyp_vcpu_run_result_t
gunyah_hyp_vcpu_run(cap_id_t cap_id, register_t resume_data_0,
		    register_t resume_data_1, register_t resume_data_2);

error_t
gunyah_hyp_vpm_group_configure(cap_id_t			vpm_group,
			       vpm_group_option_flags_t flags);

error_t
gunyah_hyp_vgic_set_mpidr_mapping(cap_id_t vic, uint64_t mask,
				  count_t aff0_shift, count_t aff1_shift,
				  count_t aff2_shift, count_t aff3_shift,
				  bool mt);

typedef struct gunyah_hyp_vcpu_run_check_result {
	error_t _Alignas(register_t) error;
	uint8_t _pad0[4]; // Pad for struct static zero initialization
	vcpu_run_state_t _Alignas(register_t) vcpu_state;
	uint8_t _pad1[4]; // Pad for struct static zero initialization
	register_t _Alignas(register_t) state_data_0;
	register_t _Alignas(register_t) state_data_1;
	register_t _Alignas(register_t) state_data_2;
} gunyah_hyp_vcpu_run_check_result_t;

gunyah_hyp_vcpu_run_check_result_t
gunyah_hyp_vcpu_run_check(cap_id_t cap_id);
