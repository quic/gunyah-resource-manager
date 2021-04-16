// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Hypervisor Call C Types
#include <guest_types.h>
// Hypervisor Call definitions
#include <guest_interface.h>

gunyah_hyp_hypervisor_identify_result_t
gunyah_hyp_hypervisor_identify(void)
{
	register uint64_t _out_x0 __asm__("x0");
	register uint64_t _out_x1 __asm__("x1");
	register uint64_t _out_x2 __asm__("x2");
	register uint64_t _out_x3 __asm__("x3");

	__asm__ volatile("hvc 0x6000"
			 : "=r"(_out_x0), "=r"(_out_x1), "=r"(_out_x2),
			   "=r"(_out_x3)
			 :
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_hypervisor_identify_result_t){
		.hyp_api_info = (hyp_api_info_t){ (uint64_t)_out_x0 },
		.api_flags_0  = (hyp_api_flags0_t){ (uint64_t)_out_x1 },
		.api_flags_1  = (hyp_api_flags1_t){ (uint64_t)_out_x2 },
		.api_flags_2  = (hyp_api_flags2_t){ (uint64_t)_out_x3 },
	};
}

gunyah_hyp_partition_create_partition_result_t
gunyah_hyp_partition_create_partition(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6001"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_partition_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_cspace_result_t
gunyah_hyp_partition_create_cspace(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6002"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_cspace_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_addrspace_result_t
gunyah_hyp_partition_create_addrspace(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6003"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_addrspace_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_memextent_result_t
gunyah_hyp_partition_create_memextent(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6004"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_memextent_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_thread_result_t
gunyah_hyp_partition_create_thread(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6005"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_thread_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_doorbell_result_t
gunyah_hyp_partition_create_doorbell(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6006"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_doorbell_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_msgqueue_result_t
gunyah_hyp_partition_create_msgqueue(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6007"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_msgqueue_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_vic_result_t
gunyah_hyp_partition_create_vic(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x600a"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_vic_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

gunyah_hyp_partition_create_vpm_group_result_t
gunyah_hyp_partition_create_vpm_group(cap_id_t src_partition, cap_id_t cspace)
{
	const register uint64_t _in_x0 __asm__("x0") =
		(uint64_t)(src_partition);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cspace);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x600b"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_partition_create_vpm_group_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

error_t
gunyah_hyp_object_activate(cap_id_t cap)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x600c"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_object_activate_from(cap_id_t cspace, cap_id_t cap)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cap);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x600d"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_object_reset(cap_id_t cap)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x600e"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_object_reset_from(cap_id_t cspace, cap_id_t cap)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cap);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x600f"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_doorbell_bind_virq(cap_id_t doorbell, cap_id_t vic, virq_t virq)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(doorbell);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(vic);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(virq);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6010"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_doorbell_unbind_virq(cap_id_t doorbell)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(doorbell);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6011"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

gunyah_hyp_doorbell_send_result_t
gunyah_hyp_doorbell_send(cap_id_t doorbell, uint64_t new_flags)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(doorbell);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(new_flags);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6012"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_doorbell_send_result_t){
		.error	   = (error_t)_out_x0,
		.old_flags = (uint64_t)_out_x1,
	};
}

gunyah_hyp_doorbell_receive_result_t
gunyah_hyp_doorbell_receive(cap_id_t doorbell, uint64_t clear_flags)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(doorbell);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(clear_flags);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6013"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_doorbell_receive_result_t){
		.error	   = (error_t)_out_x0,
		.old_flags = (uint64_t)_out_x1,
	};
}

error_t
gunyah_hyp_doorbell_reset(cap_id_t doorbell)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(doorbell);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6014"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_doorbell_mask(cap_id_t doorbell, uint64_t enable_mask,
			 uint64_t ack_mask)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(doorbell);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(enable_mask);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(ack_mask);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6015"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_msgqueue_bind_send_virq(cap_id_t msgqueue, cap_id_t vic, virq_t virq)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(vic);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(virq);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6017"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_msgqueue_bind_receive_virq(cap_id_t msgqueue, cap_id_t vic,
				      virq_t virq)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(vic);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(virq);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6018"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_msgqueue_unbind_send_virq(cap_id_t msgqueue)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6019"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_msgqueue_unbind_receive_virq(cap_id_t msgqueue)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x601a"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

gunyah_hyp_msgqueue_send_result_t
gunyah_hyp_msgqueue_send(cap_id_t msgqueue, size_t size, user_ptr_t data,
			 uint64_t send_flags)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(size);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(data);
	const register uint64_t _in_x3 __asm__("x3") = (uint64_t)(send_flags);
	const register uint64_t _in_x4 __asm__("x4") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint8_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x601b"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3),
			   "r"(_in_x4)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x5", "x6", "x7", "x8", "x9", "memory");

	return (gunyah_hyp_msgqueue_send_result_t){
		.error	  = (error_t)_out_x0,
		.not_full = (bool)_out_x1,
	};
}

gunyah_hyp_msgqueue_receive_result_t
gunyah_hyp_msgqueue_receive(cap_id_t msgqueue, user_ptr_t buffer,
			    size_t buf_size)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(buffer);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(buf_size);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");
	register uint8_t	_out_x2 __asm__("x2");

	__asm__ volatile("hvc 0x601c"
			 : "=r"(_out_x0), "=r"(_out_x1), "=r"(_out_x2)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9", "memory");

	return (gunyah_hyp_msgqueue_receive_result_t){
		.error	   = (error_t)_out_x0,
		.size	   = (size_t)_out_x1,
		.not_empty = (bool)_out_x2,
	};
}

error_t
gunyah_hyp_msgqueue_flush(cap_id_t msgqueue)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x601d"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_msgqueue_configure_send(cap_id_t msgqueue, count_t not_full_thres,
				   count_t not_full_holdoff)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint32_t _in_x1 __asm__("x1") =
		(uint32_t)(not_full_thres);
	const register uint32_t _in_x2 __asm__("x2") =
		(uint32_t)(not_full_holdoff);
	const register uint64_t _in_x3 __asm__("x3") = 0xffffffffffffffffU;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x601f"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_msgqueue_configure_receive(cap_id_t msgqueue,
				      count_t  not_empty_thres,
				      count_t  not_empty_holdoff)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint32_t _in_x1 __asm__("x1") =
		(uint32_t)(not_empty_thres);
	const register uint32_t _in_x2 __asm__("x2") =
		(uint32_t)(not_empty_holdoff);
	const register uint64_t _in_x3 __asm__("x3") = 0xffffffffffffffffU;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6020"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_msgqueue_configure(cap_id_t		     msgqueue,
			      msgqueue_create_info_t create_info)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(msgqueue);
	const register uint64_t _in_x1 __asm__("x1") =
		(uint64_t)(create_info.bf[0]);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6021"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_cspace_delete_cap_from(cap_id_t cspace, cap_id_t cap)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(cap);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6022"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

gunyah_hyp_cspace_copy_cap_from_result_t
gunyah_hyp_cspace_copy_cap_from(cap_id_t src_cspace, cap_id_t src_cap,
				cap_id_t dest_cspace, cap_rights_t rights_mask)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(src_cspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(src_cap);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(dest_cspace);
	const register uint32_t _in_x3 __asm__("x3") = (uint32_t)(rights_mask);
	const register uint64_t _in_x4 __asm__("x4") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6023"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3),
			   "r"(_in_x4)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_cspace_copy_cap_from_result_t){
		.error	 = (error_t)_out_x0,
		.new_cap = (cap_id_t)_out_x1,
	};
}

error_t
gunyah_hyp_cspace_revoke_cap_from(cap_id_t src_cspace, cap_id_t src_cap)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(src_cspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(src_cap);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6024"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_cspace_configure(cap_id_t cspace, count_t max_caps)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cspace);
	const register uint32_t _in_x1 __asm__("x1") = (uint32_t)(max_caps);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6025"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_hwirq_bind_virq(cap_id_t hwirq, cap_id_t vic, virq_t virq)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(hwirq);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(vic);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(virq);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6026"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_hwirq_unbind_virq(cap_id_t hwirq)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(hwirq);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6027"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vic_configure(cap_id_t vic, count_t max_vcpus, count_t max_virqs)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(vic);
	const register uint32_t _in_x1 __asm__("x1") = (uint32_t)(max_vcpus);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(max_virqs);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6028"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vic_attach_vcpu(cap_id_t vic, cap_id_t vcpu, index_t index)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(vic);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(vcpu);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(index);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6029"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_addrspace_attach_thread(cap_id_t addrspace, cap_id_t thread)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(addrspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(thread);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x602a"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_addrspace_map(cap_id_t addrspace, cap_id_t memextent, vmaddr_t vbase,
			 memextent_mapping_attrs_t map_attrs)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(addrspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(memextent);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(vbase);
	const register uint32_t _in_x3 __asm__("x3") =
		(uint32_t)(map_attrs.bf[0]);
	const register uint64_t _in_x4 __asm__("x4") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x602b"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3),
			   "r"(_in_x4)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_addrspace_unmap(cap_id_t addrspace, cap_id_t memextent,
			   vmaddr_t vbase)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(addrspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(memextent);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(vbase);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x602c"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_addrspace_update_access(cap_id_t addrspace, cap_id_t memextent,
				   vmaddr_t		    vbase,
				   memextent_access_attrs_t access_attrs)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(addrspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(memextent);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(vbase);
	const register uint32_t _in_x3 __asm__("x3") =
		(uint32_t)(access_attrs.bf[0]);
	const register uint64_t _in_x4 __asm__("x4") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x602d"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3),
			   "r"(_in_x4)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_addrspace_configure(cap_id_t addrspace, vmid_t vmid)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(addrspace);
	const register uint16_t _in_x1 __asm__("x1") = (uint16_t)(vmid);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x602e"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_memextent_unmap_all(cap_id_t memextent)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(memextent);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6030"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_memextent_configure(cap_id_t memextent, paddr_t phys_base,
			       size_t size, memextent_attrs_t attributes)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(memextent);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(phys_base);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(size);
	const register uint32_t _in_x3 __asm__("x3") =
		(uint32_t)(attributes.bf[0]);
	const register uint64_t _in_x4 __asm__("x4") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6031"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3),
			   "r"(_in_x4)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_memextent_configure_derive(cap_id_t memextent,
				      cap_id_t parent_memextent, size_t offset,
				      size_t size, memextent_attrs_t attributes)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(memextent);
	const register uint64_t _in_x1 __asm__("x1") =
		(uint64_t)(parent_memextent);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(offset);
	const register uint64_t _in_x3 __asm__("x3") = (uint64_t)(size);
	const register uint32_t _in_x4 __asm__("x4") =
		(uint32_t)(attributes.bf[0]);
	const register uint64_t _in_x5 __asm__("x5") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6032"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3),
			   "r"(_in_x4), "r"(_in_x5)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vcpu_configure(cap_id_t cap_id, vcpu_option_flags_t vcpu_options)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap_id);
	const register uint64_t _in_x1 __asm__("x1") =
		(uint64_t)(vcpu_options.bf[0]);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6034"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vcpu_poweron(cap_id_t cap_id, uint64_t entry_point, uint64_t context)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap_id);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(entry_point);
	const register uint64_t _in_x2 __asm__("x2") = (uint64_t)(context);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6038"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vcpu_poweroff(cap_id_t cap_id)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap_id);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6039"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vpm_group_attach_vcpu(cap_id_t vpm_group, cap_id_t vcpu,
				 index_t index)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(vpm_group);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(vcpu);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(index);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x603c"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vcpu_set_affinity(cap_id_t cap_id, cpu_index_t affinity)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap_id);
	const register uint16_t _in_x1 __asm__("x1") = (uint16_t)(affinity);
	const register uint64_t _in_x2 __asm__("x2") = 0xffffffffffffffffU;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x603d"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_cspace_attach_thread(cap_id_t cspace, cap_id_t thread)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cspace);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(thread);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x603e"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

gunyah_hyp_trace_update_class_flags_result_t
gunyah_hyp_trace_update_class_flags(uint64_t set_flags, uint64_t clear_flags)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(set_flags);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(clear_flags);
	const register uint64_t _in_x2 __asm__("x2") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x603f"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x3", "x4", "x5", "x6", "x7", "x8", "x9");

	return (gunyah_hyp_trace_update_class_flags_result_t){
		.error = (error_t)_out_x0,
		.flags = (uint64_t)_out_x1,
	};
}

error_t
gunyah_hyp_vpm_group_bind_virq(cap_id_t vpm_group, cap_id_t vic, virq_t virq)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(vpm_group);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(vic);
	const register uint32_t _in_x2 __asm__("x2") = (uint32_t)(virq);
	const register uint64_t _in_x3 __asm__("x3") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6043"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1), "r"(_in_x2), "r"(_in_x3)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x4", "x5", "x6", "x7", "x8", "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vpm_group_unbind_virq(cap_id_t vpm_group)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(vpm_group);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6044"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

gunyah_hyp_vpm_group_get_state_result_t
gunyah_hyp_vpm_group_get_state(cap_id_t vpm_group)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(vpm_group);
	const register uint64_t _in_x1 __asm__("x1") = 0x0U;
	register uint32_t	_out_x0 __asm__("x0");
	register uint64_t	_out_x1 __asm__("x1");

	__asm__ volatile("hvc 0x6045"
			 : "=r"(_out_x0), "=r"(_out_x1)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (gunyah_hyp_vpm_group_get_state_result_t){
		.error	   = (error_t)_out_x0,
		.vpm_state = (uint64_t)_out_x1,
	};
}

error_t
gunyah_hyp_vcpu_set_priority(cap_id_t cap_id, priority_t priority)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap_id);
	const register uint32_t _in_x1 __asm__("x1") = (uint32_t)(priority);
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6046"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}

error_t
gunyah_hyp_vcpu_set_timeslice(cap_id_t cap_id, nanoseconds_t timeslice)
{
	const register uint64_t _in_x0 __asm__("x0") = (uint64_t)(cap_id);
	const register uint64_t _in_x1 __asm__("x1") = (uint64_t)(timeslice);
	register uint32_t	_out_x0 __asm__("x0");

	__asm__ volatile("hvc 0x6047"
			 : "=r"(_out_x0)
			 : "r"(_in_x0), "r"(_in_x1)
			 : "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
			   "x9");

	return (error_t)_out_x0;
}
