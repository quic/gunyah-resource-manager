// Gunyah Hypervisor hypercall C bindings.
//
// Automatically generated. Do not modify.

// Hypervisor Call C Types
#include <guest_types.h>
// Hypervisor Call definitions
#include <guest_interface.h>

gunyah_hyp_hypervisor_identify_result_t
gunyah_hyp_hypervisor_identify(void)
{
	register uint64_t out_x0_ __asm__("x0");
	register uint64_t out_x1_ __asm__("x1");
	register uint64_t out_x2_ __asm__("x2");
	register uint64_t out_x3_ __asm__("x3");

	__asm__ volatile("hvc 0x6000"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_),
			   "=r"(out_x3_)
			 :
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_hypervisor_identify_result_t){
		.hyp_api_info = hyp_api_info_cast((uint64_t)out_x0_),
		.api_flags_0  = hyp_api_flags0_cast((uint64_t)out_x1_),
		.api_flags_1  = hyp_api_flags1_cast((uint64_t)out_x2_),
		.api_flags_2  = hyp_api_flags2_cast((uint64_t)out_x3_),
	};
}

gunyah_hyp_partition_create_partition_result_t
gunyah_hyp_partition_create_partition(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6001"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_partition_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_cspace_result_t
gunyah_hyp_partition_create_cspace(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6002"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_cspace_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_addrspace_result_t
gunyah_hyp_partition_create_addrspace(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6003"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_addrspace_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_memextent_result_t
gunyah_hyp_partition_create_memextent(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6004"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_memextent_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_thread_result_t
gunyah_hyp_partition_create_thread(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6005"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_thread_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_doorbell_result_t
gunyah_hyp_partition_create_doorbell(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6006"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_doorbell_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_msgqueue_result_t
gunyah_hyp_partition_create_msgqueue(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6007"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_msgqueue_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_watchdog_result_t
gunyah_hyp_partition_create_watchdog(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6009"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_watchdog_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_vic_result_t
gunyah_hyp_partition_create_vic(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x600a"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_vic_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

gunyah_hyp_partition_create_vpm_group_result_t
gunyah_hyp_partition_create_vpm_group(cap_id_t src_partition, cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x600b"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_vpm_group_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

error_t
gunyah_hyp_object_activate(cap_id_t cap)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x600c"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_object_activate_from(cap_id_t cspace, cap_id_t cap)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)cap;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x600d"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_object_reset(cap_id_t cap)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x600e"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_object_reset_from(cap_id_t cspace, cap_id_t cap)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)cap;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x600f"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_doorbell_bind_virq(cap_id_t doorbell, cap_id_t vic, virq_t virq)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)doorbell;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vic;
	register register_t	  in_x2_ __asm__("x2") = (register_t)virq;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6010"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_doorbell_unbind_virq(cap_id_t doorbell)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)doorbell;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6011"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_doorbell_send_result_t
gunyah_hyp_doorbell_send(cap_id_t doorbell, uint64_t new_flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)doorbell;
	const register register_t in_x1_ __asm__("x1") = (register_t)new_flags;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6012"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_doorbell_send_result_t){
		.error	   = (error_t)out_x0_,
		.old_flags = (uint64_t)out_x1_,
	};
}

gunyah_hyp_doorbell_receive_result_t
gunyah_hyp_doorbell_receive(cap_id_t doorbell, uint64_t clear_flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)doorbell;
	const register register_t in_x1_ __asm__("x1") =
		(register_t)clear_flags;
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");
	register uint64_t   out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6013"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_doorbell_receive_result_t){
		.error	   = (error_t)out_x0_,
		.old_flags = (uint64_t)out_x1_,
	};
}

error_t
gunyah_hyp_doorbell_reset(cap_id_t doorbell)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)doorbell;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6014"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_doorbell_mask(cap_id_t doorbell, uint64_t enable_mask,
			 uint64_t ack_mask)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)doorbell;
	register register_t in_x1_ __asm__("x1") = (register_t)enable_mask;
	register register_t in_x2_ __asm__("x2") = (register_t)ack_mask;
	register register_t in_x3_ __asm__("x3") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6015"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_msgqueue_bind_send_virq(cap_id_t msgqueue, cap_id_t vic, virq_t virq)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vic;
	register register_t	  in_x2_ __asm__("x2") = (register_t)virq;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6017"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_msgqueue_bind_receive_virq(cap_id_t msgqueue, cap_id_t vic,
				      virq_t virq)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vic;
	register register_t	  in_x2_ __asm__("x2") = (register_t)virq;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6018"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_msgqueue_unbind_send_virq(cap_id_t msgqueue)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6019"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_msgqueue_unbind_receive_virq(cap_id_t msgqueue)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x601a"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_msgqueue_send_result_t
gunyah_hyp_msgqueue_send(cap_id_t msgqueue, size_t size, user_ptr_t data,
			 msgqueue_send_flags_t send_flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	const register register_t in_x1_ __asm__("x1") = (register_t)size;
	register register_t	  in_x2_ __asm__("x2") = (register_t)data;
	register register_t in_x3_ __asm__("x3") = (register_t)send_flags.bf[0];
	register register_t in_x4_ __asm__("x4") = 0x0U;
	register error_t    out_x0_ __asm__("x0");
	register uint8_t    out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x601b"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17", "memory");

	return (gunyah_hyp_msgqueue_send_result_t){
		.error	  = (error_t)out_x0_,
		.not_full = (bool)out_x1_,
	};
}

gunyah_hyp_msgqueue_receive_result_t
gunyah_hyp_msgqueue_receive(cap_id_t msgqueue, user_ptr_t buffer,
			    size_t buf_size)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	const register register_t in_x1_ __asm__("x1") = (register_t)buffer;
	const register register_t in_x2_ __asm__("x2") = (register_t)buf_size;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");
	register uint8_t	  out_x2_ __asm__("x2");

	__asm__ volatile("hvc 0x601c"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_), "r"(in_x1_), "r"(in_x2_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17", "memory");

	return (gunyah_hyp_msgqueue_receive_result_t){
		.error	   = (error_t)out_x0_,
		.size	   = (size_t)out_x1_,
		.not_empty = (bool)out_x2_,
	};
}

error_t
gunyah_hyp_msgqueue_flush(cap_id_t msgqueue)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x601d"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_msgqueue_configure_send(cap_id_t msgqueue, count_t not_full_thres,
				   count_t not_full_holdoff)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t in_x1_ __asm__("x1") = (register_t)not_full_thres;
	register register_t in_x2_ __asm__("x2") = (register_t)not_full_holdoff;
	register register_t in_x3_ __asm__("x3") = 0xffffffffffffffffU;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x601f"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_msgqueue_configure_receive(cap_id_t msgqueue,
				      count_t  not_empty_thres,
				      count_t  not_empty_holdoff)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t in_x1_ __asm__("x1") = (register_t)not_empty_thres;
	register register_t in_x2_ __asm__("x2") =
		(register_t)not_empty_holdoff;
	register register_t in_x3_ __asm__("x3") = 0xffffffffffffffffU;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6020"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_msgqueue_configure(cap_id_t		     msgqueue,
			      msgqueue_create_info_t create_info)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)msgqueue;
	register register_t	  in_x1_ __asm__("x1") =
		(register_t)create_info.bf[0];
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6021"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_cspace_delete_cap_from(cap_id_t cspace, cap_id_t cap)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)cap;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6022"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_cspace_copy_cap_from_result_t
gunyah_hyp_cspace_copy_cap_from(cap_id_t src_cspace, cap_id_t src_cap,
				cap_id_t dest_cspace, cap_rights_t rights_mask)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)src_cspace;
	const register register_t in_x1_ __asm__("x1") = (register_t)src_cap;
	register register_t in_x2_ __asm__("x2") = (register_t)dest_cspace;
	register register_t in_x3_ __asm__("x3") = (register_t)rights_mask;
	register register_t in_x4_ __asm__("x4") = 0x0U;
	register error_t    out_x0_ __asm__("x0");
	register uint64_t   out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6023"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_cspace_copy_cap_from_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

error_t
gunyah_hyp_cspace_revoke_cap_from(cap_id_t src_cspace, cap_id_t src_cap)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)src_cspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)src_cap;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6024"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_cspace_configure(cap_id_t cspace, count_t max_caps)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)max_caps;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6025"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vic_bind_virq(cap_id_t irq_obj, cap_id_t vic, virq_t virq,
			 index_t index)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)irq_obj;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vic;
	register register_t	  in_x2_ __asm__("x2") = (register_t)virq;
	register register_t	  in_x3_ __asm__("x3") = (register_t)index;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6026"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vic_unbind_virq(cap_id_t irq_obj, index_t index)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)irq_obj;
	register register_t	  in_x1_ __asm__("x1") = (register_t)index;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6027"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vic_configure(cap_id_t vic, count_t max_vcpus, count_t max_virqs,
			 vic_option_flags_t vic_options, count_t max_msis)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vic;
	register register_t	  in_x1_ __asm__("x1") = (register_t)max_vcpus;
	register register_t	  in_x2_ __asm__("x2") = (register_t)max_virqs;
	register register_t	  in_x3_ __asm__("x3") =
		(register_t)vic_options.bf[0];
	register register_t in_x4_ __asm__("x4") = (register_t)max_msis;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6028"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vic_attach_vcpu(cap_id_t vic, cap_id_t vcpu, index_t index)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vic;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vcpu;
	register register_t	  in_x2_ __asm__("x2") = (register_t)index;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6029"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_attach_thread(cap_id_t addrspace, cap_id_t thread)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)thread;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x602a"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_map(cap_id_t addrspace, cap_id_t memextent, vmaddr_t vbase,
			 memextent_mapping_attrs_t map_attrs,
			 addrspace_map_flags_t map_flags, size_t offset,
			 size_t size)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)memextent;
	register register_t	  in_x2_ __asm__("x2") = (register_t)vbase;
	register register_t in_x3_ __asm__("x3") = (register_t)map_attrs.bf[0];
	register register_t in_x4_ __asm__("x4") = (register_t)map_flags.bf[0];
	register register_t in_x5_ __asm__("x5") = (register_t)offset;
	register register_t in_x6_ __asm__("x6") = (register_t)size;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x602b"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_), "+r"(in_x5_),
			   "+r"(in_x6_)
			 : "r"(in_x0_)
			 : "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
			   "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_unmap(cap_id_t addrspace, cap_id_t memextent,
			   vmaddr_t vbase, addrspace_map_flags_t map_flags,
			   size_t offset, size_t size)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)memextent;
	register register_t	  in_x2_ __asm__("x2") = (register_t)vbase;
	register register_t in_x3_ __asm__("x3") = (register_t)map_flags.bf[0];
	register register_t in_x4_ __asm__("x4") = (register_t)offset;
	register register_t in_x5_ __asm__("x5") = (register_t)size;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x602c"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_), "+r"(in_x5_)
			 : "r"(in_x0_)
			 : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
			   "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_update_access(cap_id_t addrspace, cap_id_t memextent,
				   vmaddr_t		    vbase,
				   memextent_access_attrs_t access_attrs,
				   addrspace_map_flags_t    map_flags,
				   size_t offset, size_t size)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)memextent;
	register register_t	  in_x2_ __asm__("x2") = (register_t)vbase;
	register register_t	  in_x3_ __asm__("x3") =
		(register_t)access_attrs.bf[0];
	register register_t in_x4_ __asm__("x4") = (register_t)map_flags.bf[0];
	register register_t in_x5_ __asm__("x5") = (register_t)offset;
	register register_t in_x6_ __asm__("x6") = (register_t)size;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x602d"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_), "+r"(in_x5_),
			   "+r"(in_x6_)
			 : "r"(in_x0_)
			 : "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
			   "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_configure(cap_id_t addrspace, vmid_t vmid)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vmid;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x602e"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_attach_vdma(cap_id_t addrspace, cap_id_t dma_device,
				 index_t index)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)dma_device;
	register register_t	  in_x2_ __asm__("x2") = (register_t)index;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x602f"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_memextent_modify(cap_id_t memextent, memextent_modify_flags_t flags,
			    size_t offset, size_t size)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)memextent;
	register register_t in_x1_ __asm__("x1") = (register_t)flags.bf[0];
	register register_t in_x2_ __asm__("x2") = (register_t)offset;
	register register_t in_x3_ __asm__("x3") = (register_t)size;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6030"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_memextent_configure(cap_id_t memextent, paddr_t phys_base,
			       size_t size, memextent_attrs_t attributes)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)memextent;
	register register_t	  in_x1_ __asm__("x1") = (register_t)phys_base;
	register register_t	  in_x2_ __asm__("x2") = (register_t)size;
	register register_t in_x3_ __asm__("x3") = (register_t)attributes.bf[0];
	register register_t in_x4_ __asm__("x4") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6031"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_memextent_configure_derive(cap_id_t memextent,
				      cap_id_t parent_memextent, size_t offset,
				      size_t size, memextent_attrs_t attributes)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)memextent;
	register register_t in_x1_ __asm__("x1") = (register_t)parent_memextent;
	register register_t in_x2_ __asm__("x2") = (register_t)offset;
	register register_t in_x3_ __asm__("x3") = (register_t)size;
	register register_t in_x4_ __asm__("x4") = (register_t)attributes.bf[0];
	register register_t in_x5_ __asm__("x5") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6032"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_), "+r"(in_x5_)
			 : "r"(in_x0_)
			 : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
			   "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_configure(cap_id_t cap_id, vcpu_option_flags_t vcpu_options)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap_id;
	register register_t	  in_x1_ __asm__("x1") =
		(register_t)vcpu_options.bf[0];
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6034"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_poweron(cap_id_t cap_id, uint64_t entry_point, uint64_t context,
			vcpu_poweron_flags_t flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap_id;
	register register_t in_x1_ __asm__("x1") = (register_t)entry_point;
	register register_t in_x2_ __asm__("x2") = (register_t)context;
	register register_t in_x3_ __asm__("x3") = (register_t)flags.bf[0];
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6038"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_poweroff(cap_id_t cap_id, vcpu_poweroff_flags_t flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap_id;
	register register_t in_x1_ __asm__("x1") = (register_t)flags.bf[0];
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6039"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_kill(cap_id_t cap_id)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap_id;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x603a"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_scheduler_yield(scheduler_yield_control_t control, uint64_t arg1)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)control.bf[0];
	register register_t in_x1_ __asm__("x1") = (register_t)arg1;
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x603b"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vpm_group_attach_vcpu(cap_id_t vpm_group, cap_id_t vcpu,
				 index_t index)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vpm_group;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vcpu;
	register register_t	  in_x2_ __asm__("x2") = (register_t)index;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x603c"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_set_affinity(cap_id_t cap_id, uint64_t arg1,
			     vcpu_affinity_type_t type)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap_id;
	register register_t	  in_x1_ __asm__("x1") = (register_t)arg1;
	register sregister_t	  in_x2_ __asm__("x2") = (sregister_t)type;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x603d"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_cspace_attach_thread(cap_id_t cspace, cap_id_t thread)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)thread;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x603e"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_trace_update_class_flags_result_t
gunyah_hyp_trace_update_class_flags(uint64_t set_flags, uint64_t clear_flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)set_flags;
	const register register_t in_x1_ __asm__("x1") =
		(register_t)clear_flags;
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");
	register uint64_t   out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x603f"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_trace_update_class_flags_result_t){
		.error = (error_t)out_x0_,
		.flags = (uint64_t)out_x1_,
	};
}

error_t
gunyah_hyp_watchdog_attach_vcpu(cap_id_t watchdog, cap_id_t vcpu)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)watchdog;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vcpu;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6040"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_watchdog_bind_virq(cap_id_t watchdog, cap_id_t vic, virq_t virq,
			      watchdog_bind_option_flags_t bind_options)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)watchdog;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vic;
	register register_t	  in_x2_ __asm__("x2") = (register_t)virq;
	register register_t	  in_x3_ __asm__("x3") =
		(register_t)bind_options.bf[0];
	register error_t out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6041"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_watchdog_unbind_virq(cap_id_t		     watchdog,
				watchdog_bind_option_flags_t unbind_options)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)watchdog;
	register register_t	  in_x1_ __asm__("x1") =
		(register_t)unbind_options.bf[0];
	register error_t out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6042"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vpm_group_bind_virq(cap_id_t vpm_group, cap_id_t vic, virq_t virq)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vpm_group;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vic;
	register register_t	  in_x2_ __asm__("x2") = (register_t)virq;
	register register_t	  in_x3_ __asm__("x3") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6043"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vpm_group_unbind_virq(cap_id_t vpm_group)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vpm_group;
	register register_t	  in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6044"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_vpm_group_get_state_result_t
gunyah_hyp_vpm_group_get_state(cap_id_t vpm_group)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vpm_group;
	const register register_t in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6045"
			 : "=r"(out_x0_), "=r"(out_x1_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (gunyah_hyp_vpm_group_get_state_result_t){
		.error	   = (error_t)out_x0_,
		.vpm_state = (uint64_t)out_x1_,
	};
}

error_t
gunyah_hyp_vcpu_set_priority(cap_id_t cap_id, priority_t priority)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap_id;
	register register_t	  in_x1_ __asm__("x1") = (register_t)priority;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6046"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_set_timeslice(cap_id_t cap_id, nanoseconds_t timeslice)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)cap_id;
	register register_t	  in_x1_ __asm__("x1") = (register_t)timeslice;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6047"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_partition_create_virtio_backend_result_t
gunyah_hyp_partition_create_virtio_backend(cap_id_t src_partition,
					   cap_id_t cspace)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)src_partition;
	const register register_t in_x1_ __asm__("x1") = (register_t)cspace;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6048"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_partition_create_virtio_backend_result_t){
		.error	 = (error_t)out_x0_,
		.new_cap = (cap_id_t)out_x1_,
	};
}

error_t
gunyah_hyp_virtio_mmio_configure(cap_id_t virtio_backend, cap_id_t memextent,
				 count_t		       vqs_num,
				 virtio_backend_option_flags_t flags,
				 virtio_device_type_t	       device_type)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = (register_t)memextent;
	register register_t in_x2_ __asm__("x2") = (register_t)vqs_num;
	register register_t in_x3_ __asm__("x3") = (register_t)flags.bf[0];
	register register_t in_x4_ __asm__("x4") = (register_t)device_type;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6049"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_mmio_frontend_bind_virq(cap_id_t virtio_backend, cap_id_t vic,
					  virq_t virq)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = (register_t)vic;
	register register_t in_x2_ __asm__("x2") = (register_t)virq;
	register register_t in_x3_ __asm__("x3") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x604a"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_mmio_frontend_unbind_virq(cap_id_t virtio_backend)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x604b"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_backend_bind_virq(cap_id_t virtio_backend, cap_id_t vic,
				    virq_t virq)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = (register_t)vic;
	register register_t in_x2_ __asm__("x2") = (register_t)virq;
	register register_t in_x3_ __asm__("x3") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x604c"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_backend_unbind_virq(cap_id_t virtio_backend)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x604d"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_backend_notify(cap_id_t virtio_backend,
				 uint32_t interrupt_status)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = (register_t)interrupt_status;
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x604e"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_backend_set_dev_features(cap_id_t virtio_backend,
					   uint32_t feature_sel,
					   uint32_t dev_feat)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = (register_t)feature_sel;
	register register_t in_x2_ __asm__("x2") = (register_t)dev_feat;
	register register_t in_x3_ __asm__("x3") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x604f"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_backend_set_queue_size_max(cap_id_t virtio_backend,
					     uint32_t queue_sel,
					     uint32_t queue_size_max)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = (register_t)queue_sel;
	register register_t in_x2_ __asm__("x2") = (register_t)queue_size_max;
	register register_t in_x3_ __asm__("x3") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6050"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_virtio_backend_get_drv_features_result_t
gunyah_hyp_virtio_backend_get_drv_features(cap_id_t virtio_backend,
					   uint32_t feature_sel)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	const register register_t in_x1_ __asm__("x1") =
		(register_t)feature_sel;
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");
	register uint32_t   out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6051"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_virtio_backend_get_drv_features_result_t){
		.error	  = (error_t)out_x0_,
		.drv_feat = (uint32_t)out_x1_,
	};
}

gunyah_hyp_virtio_backend_get_queue_info_result_t
gunyah_hyp_virtio_backend_get_queue_info(cap_id_t virtio_backend,
					 uint32_t queue_sel)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	const register register_t in_x1_ __asm__("x1") = (register_t)queue_sel;
	const register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint16_t	  out_x1_ __asm__("x1");
	register uint8_t	  out_x2_ __asm__("x2");
	register uint64_t	  out_x3_ __asm__("x3");
	register uint64_t	  out_x4_ __asm__("x4");
	register uint64_t	  out_x5_ __asm__("x5");

	__asm__ volatile("hvc 0x6052"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_),
			   "=r"(out_x3_), "=r"(out_x4_), "=r"(out_x5_)
			 : "r"(in_x0_), "r"(in_x1_), "r"(in_x2_)
			 : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
			   "x14", "x15", "x16", "x17");

	return (gunyah_hyp_virtio_backend_get_queue_info_result_t){
		.error	     = (error_t)out_x0_,
		.queue_size  = (uint16_t)out_x1_,
		.queue_ready = (bool)out_x2_,
		.queue_desc  = (uint64_t)out_x3_,
		.queue_drv   = (uint64_t)out_x4_,
		.queue_dev   = (uint64_t)out_x5_,
	};
}

gunyah_hyp_virtio_backend_get_notification_result_t
gunyah_hyp_virtio_backend_get_notification(cap_id_t virtio_backend)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	const register register_t in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");
	register uint64_t	  out_x2_ __asm__("x2");

	__asm__ volatile("hvc 0x6053"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_virtio_backend_get_notification_result_t){
		.error	    = (error_t)out_x0_,
		.vqs_bitmap = (register_t)out_x1_,
		.reason = virtio_backend_notify_reason_cast((uint64_t)out_x2_),
	};
}

error_t
gunyah_hyp_virtio_backend_acknowledge_reset(cap_id_t virtio_backend)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6054"
			 : "=r"(out_x0_), "+r"(in_x1_)
			 : "r"(in_x0_)
			 : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
			   "x10", "x11", "x12", "x13", "x14", "x15", "x16",
			   "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_virtio_backend_update_status(cap_id_t	virtio_backend,
					virtio_status_t status)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)virtio_backend;
	register register_t in_x1_ __asm__("x1") = (register_t)status.bf[0];
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6055"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vic_bind_msi_source(cap_id_t vic, cap_id_t msi_source)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vic;
	register register_t	  in_x1_ __asm__("x1") = (register_t)msi_source;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6056"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_prng_get_entropy_result_t
gunyah_hyp_prng_get_entropy(count_t num_bytes)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)num_bytes;
	const register register_t in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint32_t	  out_x1_ __asm__("x1");
	register uint32_t	  out_x2_ __asm__("x2");
	register uint32_t	  out_x3_ __asm__("x3");
	register uint32_t	  out_x4_ __asm__("x4");

	__asm__ volatile("hvc 0x6057"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_),
			   "=r"(out_x3_), "=r"(out_x4_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_prng_get_entropy_result_t){
		.error = (error_t)out_x0_,
		.data0 = (uint32_t)out_x1_,
		.data1 = (uint32_t)out_x2_,
		.data2 = (uint32_t)out_x3_,
		.data3 = (uint32_t)out_x4_,
	};
}

error_t
gunyah_hyp_watchdog_configure(cap_id_t		      watchdog,
			      watchdog_option_flags_t watchdog_options)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)watchdog;
	register register_t	  in_x1_ __asm__("x1") =
		(register_t)watchdog_options.bf[0];
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6058"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_cspace_revoke_caps_from(cap_id_t src_cspace, cap_id_t master_cap)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)src_cspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)master_cap;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6059"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_addrspace_lookup_result_t
gunyah_hyp_addrspace_lookup(cap_id_t addrspace, cap_id_t memextent,
			    vmaddr_t vbase, size_t size)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	const register register_t in_x1_ __asm__("x1") = (register_t)memextent;
	const register register_t in_x2_ __asm__("x2") = (register_t)vbase;
	const register register_t in_x3_ __asm__("x3") = (register_t)size;
	register register_t	  in_x4_ __asm__("x4") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");
	register uint64_t	  out_x2_ __asm__("x2");
	register uint32_t	  out_x3_ __asm__("x3");

	__asm__ volatile("hvc 0x605a"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_),
			   "=r"(out_x3_), "+r"(in_x4_)
			 : "r"(in_x0_), "r"(in_x1_), "r"(in_x2_), "r"(in_x3_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_addrspace_lookup_result_t){
		.error	   = (error_t)out_x0_,
		.offset	   = (size_t)out_x1_,
		.size	   = (size_t)out_x2_,
		.map_attrs = memextent_mapping_attrs_cast((uint32_t)out_x3_),
	};
}

error_t
gunyah_hyp_addrspace_configure_info_area(cap_id_t addrspace,
					 cap_id_t info_area_me, vmaddr_t ipa)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t in_x1_ __asm__("x1") = (register_t)info_area_me;
	register register_t in_x2_ __asm__("x2") = (register_t)ipa;
	register register_t in_x3_ __asm__("x3") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x605b"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_bind_virq(cap_id_t vcpu, cap_id_t vic, virq_t virq,
			  vcpu_virq_type_t virq_type)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vcpu;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vic;
	register register_t	  in_x2_ __asm__("x2") = (register_t)virq;
	register register_t	  in_x3_ __asm__("x3") = (register_t)virq_type;
	register register_t	  in_x4_ __asm__("x4") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x605c"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_unbind_virq(cap_id_t vcpu, vcpu_virq_type_t virq_type)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vcpu;
	register register_t	  in_x1_ __asm__("x1") = (register_t)virq_type;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x605d"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_configure_range(cap_id_t addrspace, vmaddr_t vbase,
				     size_t			    size,
				     addrspace_range_configure_op_t op)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vbase;
	register register_t	  in_x2_ __asm__("x2") = (register_t)size;
	register register_t	  in_x3_ __asm__("x3") = (register_t)op;
	register register_t	  in_x4_ __asm__("x4") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6060"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_memextent_donate(memextent_donate_options_t options, cap_id_t from,
			    cap_id_t to, size_t offset, size_t size)
{
	const register register_t in_x0_ __asm__("x0") =
		(register_t)options.bf[0];
	register register_t in_x1_ __asm__("x1") = (register_t)from;
	register register_t in_x2_ __asm__("x2") = (register_t)to;
	register register_t in_x3_ __asm__("x3") = (register_t)offset;
	register register_t in_x4_ __asm__("x4") = (register_t)size;
	register register_t in_x5_ __asm__("x5") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6061"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_), "+r"(in_x5_)
			 : "r"(in_x0_)
			 : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
			   "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_addrspace_attach_vdevice(cap_id_t addrspace, cap_id_t vdevice,
				    index_t index, vmaddr_t vbase, size_t size,
				    addrspace_attach_vdevice_flags_t flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	register register_t	  in_x1_ __asm__("x1") = (register_t)vdevice;
	register register_t	  in_x2_ __asm__("x2") = (register_t)index;
	register register_t	  in_x3_ __asm__("x3") = (register_t)vbase;
	register register_t	  in_x4_ __asm__("x4") = (register_t)size;
	register register_t	  in_x5_ __asm__("x5") = (register_t)flags.raw;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6062"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_), "+r"(in_x5_)
			 : "r"(in_x0_)
			 : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
			   "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_watchdog_manage(cap_id_t watchdog, watchdog_manage_op_t operation)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)watchdog;
	register register_t	  in_x1_ __asm__("x1") = (register_t)operation;
	register register_t	  in_x2_ __asm__("x2") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6063"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vcpu_register_write(cap_id_t vcpu, vcpu_register_set_t register_set,
			       index_t register_index, uint64_t value)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vcpu;
	register register_t in_x1_ __asm__("x1") = (register_t)register_set;
	register register_t in_x2_ __asm__("x2") = (register_t)register_index;
	register register_t in_x3_ __asm__("x3") = (register_t)value;
	register register_t in_x4_ __asm__("x4") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6064"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_vcpu_run_result_t
gunyah_hyp_vcpu_run(cap_id_t vcpu, register_t resume_data_0,
		    register_t resume_data_1, register_t resume_data_2)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vcpu;
	const register register_t in_x1_ __asm__("x1") =
		(register_t)resume_data_0;
	const register register_t in_x2_ __asm__("x2") =
		(register_t)resume_data_1;
	const register register_t in_x3_ __asm__("x3") =
		(register_t)resume_data_2;
	const register register_t in_x4_ __asm__("x4") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register vcpu_run_state_t out_x1_ __asm__("x1");
	register uint64_t	  out_x2_ __asm__("x2");
	register uint64_t	  out_x3_ __asm__("x3");
	register uint64_t	  out_x4_ __asm__("x4");

	__asm__ volatile("hvc 0x6065"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_),
			   "=r"(out_x3_), "=r"(out_x4_)
			 : "r"(in_x0_), "r"(in_x1_), "r"(in_x2_), "r"(in_x3_),
			   "r"(in_x4_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_vcpu_run_result_t){
		.error	      = (error_t)out_x0_,
		.vcpu_state   = (vcpu_run_state_t)out_x1_,
		.state_data_0 = (register_t)out_x2_,
		.state_data_1 = (register_t)out_x3_,
		.state_data_2 = (register_t)out_x4_,
	};
}

error_t
gunyah_hyp_vpm_group_configure(cap_id_t			vpm_group,
			       vpm_group_option_flags_t flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vpm_group;
	register register_t in_x1_ __asm__("x1") = (register_t)flags.bf[0];
	register register_t in_x2_ __asm__("x2") = 0x0U;
	register error_t    out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6066"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (error_t)out_x0_;
}

error_t
gunyah_hyp_vgic_set_mpidr_mapping(cap_id_t vic, uint64_t mask,
				  count_t aff0_shift, count_t aff1_shift,
				  count_t aff2_shift, count_t aff3_shift,
				  bool mt)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vic;
	register register_t	  in_x1_ __asm__("x1") = (register_t)mask;
	register register_t	  in_x2_ __asm__("x2") = (register_t)aff0_shift;
	register register_t	  in_x3_ __asm__("x3") = (register_t)aff1_shift;
	register register_t	  in_x4_ __asm__("x4") = (register_t)aff2_shift;
	register register_t	  in_x5_ __asm__("x5") = (register_t)aff3_shift;
	register register_t	  in_x6_ __asm__("x6") = (register_t)mt;
	register error_t	  out_x0_ __asm__("x0");

	__asm__ volatile("hvc 0x6067"
			 : "=r"(out_x0_), "+r"(in_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_), "+r"(in_x5_),
			   "+r"(in_x6_)
			 : "r"(in_x0_)
			 : "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
			   "x15", "x16", "x17");

	return (error_t)out_x0_;
}

gunyah_hyp_vcpu_run_check_result_t
gunyah_hyp_vcpu_run_check(cap_id_t vcpu)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)vcpu;
	const register register_t in_x1_ __asm__("x1") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register vcpu_run_state_t out_x1_ __asm__("x1");
	register uint64_t	  out_x2_ __asm__("x2");
	register uint64_t	  out_x3_ __asm__("x3");
	register uint64_t	  out_x4_ __asm__("x4");

	__asm__ volatile("hvc 0x6068"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_),
			   "=r"(out_x3_), "=r"(out_x4_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_vcpu_run_check_result_t){
		.error	      = (error_t)out_x0_,
		.vcpu_state   = (vcpu_run_state_t)out_x1_,
		.state_data_0 = (register_t)out_x2_,
		.state_data_1 = (register_t)out_x3_,
		.state_data_2 = (register_t)out_x4_,
	};
}

gunyah_hyp_addrspace_modify_pages_result_t
gunyah_hyp_addrspace_modify_pages(cap_id_t addrspace, vmaddr_t vbase,
				  size_t			 size,
				  addrspace_modify_pages_flags_t flags)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	const register register_t in_x1_ __asm__("x1") = (register_t)vbase;
	register register_t	  in_x2_ __asm__("x2") = (register_t)size;
	register register_t in_x3_ __asm__("x3") = (register_t)flags.bf[0];
	register error_t    out_x0_ __asm__("x0");
	register uint64_t   out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x6069"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_),
			   "+r"(in_x3_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			   "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_addrspace_modify_pages_result_t){
		.error		= (error_t)out_x0_,
		.size_remaining = (size_t)out_x1_,
	};
}

gunyah_hyp_addrspace_find_info_area_result_t
gunyah_hyp_addrspace_find_info_area(void)
{
	const register register_t in_x0_ __asm__("x0") = 0x0U;
	register error_t	  out_x0_ __asm__("x0");
	register uint64_t	  out_x1_ __asm__("x1");
	register uint64_t	  out_x2_ __asm__("x2");

	__asm__ volatile("hvc 0x606a"
			 : "=r"(out_x0_), "=r"(out_x1_), "=r"(out_x2_)
			 : "r"(in_x0_)
			 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			   "x11", "x12", "x13", "x14", "x15", "x16", "x17");

	return (gunyah_hyp_addrspace_find_info_area_result_t){
		.error = (error_t)out_x0_,
		.base  = (vmaddr_t)out_x1_,
		.size  = (size_t)out_x2_,
	};
}

gunyah_hyp_addrspace_info_area_add_entry_result_t
gunyah_hyp_addrspace_info_area_add_entry(
	cap_id_t addrspace, addrspace_info_area_entry_type_t type,
	user_ptr_t data, addrspace_info_area_entry_data_info_t data_info)
{
	const register register_t in_x0_ __asm__("x0") = (register_t)addrspace;
	const register register_t in_x1_ __asm__("x1") = (register_t)type.bf[0];
	register register_t	  in_x2_ __asm__("x2") = (register_t)data;
	register register_t in_x3_ __asm__("x3") = (register_t)data_info.bf[0];
	register register_t in_x4_ __asm__("x4") = 0x0U;
	register error_t    out_x0_ __asm__("x0");
	register uint64_t   out_x1_ __asm__("x1");

	__asm__ volatile("hvc 0x606b"
			 : "=r"(out_x0_), "=r"(out_x1_), "+r"(in_x2_),
			   "+r"(in_x3_), "+r"(in_x4_)
			 : "r"(in_x0_), "r"(in_x1_)
			 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
			   "x13", "x14", "x15", "x16", "x17", "memory");

	return (gunyah_hyp_addrspace_info_area_add_entry_result_t){
		.error = (error_t)out_x0_,
		.ipa   = (vmaddr_t)out_x1_,
	};
}
