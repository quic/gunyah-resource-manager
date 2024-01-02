// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// IRQ manager design:
//
// Requirements:
// 1. Track HW IRQ ownership
// 2. Track HW IRQ lending state
// 3. Manage VM's IRQ namespace
// 4. Manage VM's virqs (partial)
// 5. Track reserved IRQ numbers for future HW assignments / lends etc.
// 6. Handle IRQ lending, accepting, release, return protocol
//    IRQ handles etc.
//
// We don't handle cpulocal irq partitions (IRQs bound to a single or group of
// CPUs).
// We don't support lending a VM's virqs.
//
// Every IRQ, whether it is cpulocal or global (or cpulocal partitioned) has a
// unique HW irq number in the irq_manager interface. The mapping to HW irqs is
// platform specific.
//
// IRQ types are handled separately in the API only where the difference is
// important.

// Initialize the irq_manager globally
error_t
irq_manager_init(const rm_env_data_t *env_data);

// De-initialize the irq_manager
void
irq_manager_deinit(void);

// Add a HW IRQ to the irq_manager
// Requires cap-id and owner VMID
error_t
irq_manager_hwirq_add(uint32_t hw_irq_number, cap_id_t capid, vmid_t owner);

// Donate a HW IRQ to another VMID
// The HW IRQ must not be mapped or currently lending
error_t
irq_manager_hwirq_donate(uint32_t hw_irq_number, vmid_t owner);

// Lookup the owner of a HW global IRQ
vmid_result_t
irq_manager_hwirq_get_owner(uint32_t hw_irq_number);

// Initialize the irq_manager structures for a VM
error_t
irq_manager_vm_init(vm_t *vm, cap_id_t vic, count_t max_irq);

// Indicate to the irq_manager that the VM is being reset
void
irq_manager_vm_reset(vm_t *vm);

// De-initialize and clean-up VM irq_manager structures
// Requires all interrupts to be unmapped from the VM
void
irq_manager_vm_deinit(vm_t *vm);

// Allocate and reserve a global IRQ number in the VM. A reserved IRQ won't be
// available for subsequent allocation, however it may be used when mapping
// interrupts.
uint32_result_t
irq_manager_vm_alloc_global(const vm_t *vm);

// Reserve a global IRQ number in the VM. A reserved IRQ won't be available for
// subsequent allocation, however it may be used when mapping interrupts.
error_t
irq_manager_vm_reserve_global(const vm_t *vm, uint32_t irq_number);

// Un-reserve / free a reserved global IRQ.
// The IRQ may not be mapped or currently lending.
error_t
irq_manager_vm_free_global(const vm_t *vm, uint32_t irq_number);

// Map all IRQs owned by the VM as direct (1:1)
// Typically only used for HLOS init.
error_t
irq_manager_vm_hwirq_map_all_direct(const vm_t *vm);

// Map a HW IRQ to the VM.
// If `alloc` is true, the irq_number is assumed to be unused and is allocated.
// If false, it is assumed that the IRQ number previously allocated, such as
// via irq_manager_vm_alloc_global().
// Note, this does not actually map the virq, since binding virqs is source
// specific.
error_t
irq_manager_vm_hwirq_map(const vm_t *vm, uint32_t irq_number,
			 uint32_t hw_irq_number, bool alloc);

// Unmap a HW IRQ from a VM.
// If `free_irq` is true, the irq_number is deallocated. If false, the IRQ
// number becomes reserved.
// Note, this does not actually map the virq, since binding virqs is source
// specific.
error_t
irq_manager_vm_hwirq_unmap(const vm_t *vm, uint32_t irq_number, bool free_irq);

// Add a virq to the VM's irq_manager tracking.
// If `alloc` is true, the irq_number is assumed to be unused and is allocated.
// If false, it is assumed that the IRQ number previously allocated, such as
// via irq_manager_vm_alloc_global().
// Note, this does not actually map the virq, since binding virqs is source
// specific.
error_t
irq_manager_vm_virq_map(const vm_t *vm, uint32_t irq_number, bool alloc);

// Remove an VIRQ from the VM's irq_manager tracking.
// If `free_irq` is true, the IRQ number is freed, otherwise it remains a
// reserved IRQ number.
error_t
irq_manager_vm_virq_unmap(const vm_t *vm, uint32_t irq_number, bool free_irq);

// Lend a restricted IRQ to a VM.
// This is a temporary API, will be removed once restricted IRQs are replaced
// with IRQ ownership configuration.
error_t
irq_manager_vm_restricted_lend(const vm_t *vm, uint32_t irq_number,
			       uint32_t hw_irq_number);

// Static lend an HLOS IRQ to a trusted VM.
// This is a temporary API, will be removed once static lend IRQs are replaced
// with dynamic IRQ lends.
error_t
irq_manager_vm_static_lend(const vm_t *vm, uint32_t irq_number,
			   uint32_t hw_irq_number);

// Handle VM reset and release all borrowed IRQs
bool
vm_reset_handle_release_irqs(vmid_t vmid);

// IRQ-lending handling
bool
irq_manager_lending_msg_handler(vmid_t client_id, uint32_t msg_id,
				uint16_t seq_num, void *buf, size_t len);
