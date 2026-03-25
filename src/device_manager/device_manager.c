// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/range_list.h>
#include <utils/vector.h>

#include <compiler.h>
#include <device_manager.h>
#include <event.h>
#include <guest_interface.h>
#include <irq_arch.h>
#include <irq_manager.h>
#include <log.h>
#include <mem_region.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <panic.h>
#include <platform.h>
#include <platform_devices.h>
#include <platform_vm_config.h>
#include <random.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

#include "device_manager-internal.h"
#include "pcie-internal.h"

#if defined(CONFIG_DEVICE_MANAGER) && CONFIG_DEVICE_MANAGER

#define FLAGS_VALID(f, t) (((f) & (uint8_t)(~t##_MASK)) == 0U)
#define CMP_DESCR(a, b)                                                        \
	(((a)->resource.descriptors.descriptor0 ==                             \
	  (b)->descriptors.descriptor0) &&                                     \
	 ((a)->resource.descriptors.descriptor1 ==                             \
	  (b)->descriptors.descriptor1) &&                                     \
	 ((a)->resource.descriptors.descriptor2 ==                             \
	  (b)->descriptors.descriptor2) &&                                     \
	 ((a)->resource.descriptors.descriptor3 ==                             \
	  (b)->descriptors.descriptor3))

static const rm_env_data_t *rm_env_data;
static vector_t		   *host_buses;
static index_t		    plat_devices_bus_index = ~(index_t)0U;
// Range list for keeping track of the MMIO ranges used by all devices managed
// by the device manager. This is used as a fast lookup of used memory ranges,
// e.g. to allow querying the device mamanger whether a particular memory range
// belongs to a device.
static range_list_t *mmio_ranges;

static void
device_manager_notify_released(vmid_t vmid, device_handle_t handle);

static void
device_manager_notify_accepted(vmid_t vmid, vmid_t participant,
			       device_handle_t handle);

static error_t
device_manager_detach_smmu(vm_t *vm, const device_t *device, count_t num_iommu,
			   bool try_rollback);

static error_t
device_manager_attach_smmu(vm_t *vm, const device_t *device, count_t num_iommu,
			   bool try_rollback);

// Small helper functions

static void
vector_free(vector_t **vector)
{
	assert(vector != NULL);
	assert(*vector != NULL);

	vector_deinit(*vector);
	*vector = NULL;
}

static count_t
vector_size_ncheck(const vector_t *vector)
{
	return (vector != NULL) ? vector_size(vector) : 0U;
}

static bool
check_same_handle(void *val, void *target)
{
	device_handle_t *cmp_handle = (device_handle_t *)val;
	device_handle_t *tgt_handle = (device_handle_t *)target;

	assert(cmp_handle != NULL);
	assert(tgt_handle != NULL);

	return (*cmp_handle == *tgt_handle);
}

static error_t
insert_device_range(device_t *device, paddr_t addr, size_t size)
{
	error_t		      err = OK;
	range_list_find_ret_t range_r;

	assert(mmio_ranges != NULL);

	range_r = range_list_find_range(mmio_ranges, addr, size, PAGE_SIZE);

	if (range_r.err == OK) {
		LOG("device-manager: Duplicate MMIO range: 0x%lx (0x%lx bytes)\n",
		    addr, size);
		err = ERROR_EXISTING_MAPPING;
		goto out;
	}

	if (range_r.err != ERROR_NORESOURCES) {
		err = range_r.err;
		goto out;
	}

	err = range_list_insert(mmio_ranges, addr, size, (uintptr_t)device);

out:

	return err;
}

static cap_id_t
get_smmuv2_cap(uint64_t smmu_addr)
{
	const rm_smmu_env_data_t *smmu_env_data = rm_get_smmuv2_env();
	count_t			  num_v2_smmu	= rm_get_num_v2_smmu();
	cap_id_t		  iommu_cap	= CSPACE_CAP_INVALID;

	for (index_t i = 0; i < num_v2_smmu; i++) {
		if (smmu_env_data[i].smmu_addr == smmu_addr) {
			iommu_cap = smmu_env_data[i].smmuv2_cap;
			break;
		}
	}

	return iommu_cap;
}

// RPC message handlers and corresponding helper functions

static count_result_t
device_get_resource_count(const device_t *device)
{
	count_result_t res = { .r = 0U, .e = OK };
	count_t	       vs;

	vs = vector_size_ncheck(device->mmio_regs);
	if (util_add_overflows(res.r, vs)) {
		res.e = ERROR_NOMEM;
		goto out;
	}
	res.r += vs;

	vs = vector_size_ncheck(device->irqs);
	if (util_add_overflows(res.r, vs)) {
		res.e = ERROR_NOMEM;
		goto out;
	}
	res.r += vs;

	vs = vector_size_ncheck(device->iommu_endpoints);
	if (util_add_overflows(res.r, vs)) {
		res.e = ERROR_NOMEM;
		goto out;
	}
	res.r += vs;

	vs = vector_size_ncheck(device->msi_endpoints);
	if (util_add_overflows(res.r, vs)) {
		res.e = ERROR_NOMEM;
		goto out;
	}
	res.r += vs;

	vs = vector_size_ncheck(device->pcie_functions);
	if (util_add_overflows(res.r, vs)) {
		res.e = ERROR_NOMEM;
		goto out;
	}
	res.r += vs;

out:

	return res;
}

static device_handle_t
device_manager_handle_alloc(const host_bus_t *bus, uint32_t device_index)
{
	device_handle_t handle;

	assert(bus != NULL);

	handle = (util_add_overflows(bus->rand_base, device_index))
			 ? DEVICE_MGR_INVALID_HANDLE
			 : (bus->rand_base + device_index);

	return handle;
}

static device_lookup_result_t
device_manager_handle_lookup(device_handle_t handle)
{
	uint32_t	       bus_idx;
	host_bus_t	      *bus;
	vector_t	      *buses;
	device_t	      *device;
	device_lookup_result_t res = { .device = NULL, .bus_index = 0U };

	buses = host_buses;

	if (handle == DEVICE_MGR_INVALID_HANDLE) {
		goto out;
	}

	foreach_vector_ptr (host_bus_t, buses, bus_idx, bus) {
		uint32_t dev_idx;

		assert(bus->devices != NULL);

		// Check if the supplied handle is outside of this bus's range.
		if (!((handle >= bus->rand_base) &&
		      (handle < (bus->rand_base + DEVICES_PER_BUS_MAX)))) {
			continue;
		}

		dev_idx = handle - bus->rand_base;
		if (dev_idx >= vector_size(bus->devices)) {
			goto out;
		}

		device = vector_at_ptr(device_t, bus->devices, dev_idx);
		if (device == NULL) {
			goto out;
		}

		res.device    = device;
		res.bus_index = bus_idx;
		break;
	}

out:

	return res;
}

static host_bus_lookup_result_t
device_manager_bus_handle_lookup(device_handle_t handle)
{
	vector_t		*buses;
	host_bus_t		*bus;
	index_t			 bus_idx;
	host_bus_lookup_result_t res = { .index = 0U, .bus = NULL };

	assert(host_buses != NULL);

	if (handle == DEVICE_MGR_INVALID_HANDLE) {
		goto out;
	}

	buses	= host_buses;
	res.err = ERROR_ARGUMENT_INVALID;

	foreach_vector_ptr (host_bus_t, buses, bus_idx, bus) {
		// At the moment, there is no ownership of host buses, so if the
		// VM can find out a valid bus handle, it can lock down the bus.
		// FIXME: QC RM issue #75
		if (bus->handle == handle) {
			res.bus	  = bus;
			res.index = bus_idx;
			res.err	  = OK;
			break;
		}
	}

out:

	return res;
}

static error_t
device_manager_unmap_mmio(vm_t *vm, const device_t *device)
{
	error_t	 err;
	cap_id_t me_cap = device->me_cap;

	if (me_cap == CSPACE_CAP_INVALID) {
		err = ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	// Assume that we're dealing with host-physical addresses and
	// that devices are mapped 1:1 to IPA space.
	err = vm_memory_unmap_whole_extent(vm, VM_MEMUSE_IO, me_cap);
	if (err != OK) {
		LOG_ERR(err);
	}

out:

	return err;
}

static error_t
device_manager_map_mmio(vm_t *vm, const device_t *device)
{
	error_t	 err;
	cap_id_t me_cap = device->me_cap;

	if (me_cap == CSPACE_CAP_INVALID) {
		err = ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	err = vm_memory_map(vm, VM_MEMUSE_IO, me_cap, 0U, PGTABLE_ACCESS_RW,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (err != OK) {
		LOG_ERR(err);
	}

out:

	return err;
}

static error_t
device_manager_attach_smmu(vm_t *vm, const device_t *device, count_t num_iommu,
			   bool try_rollback)
{
	error_t		   err, rb_err;
	index_t		   iommu_idx;
	device_resource_t *iommu_res;
	// FIXME: Distinguish between v2 and v3.
	cap_id_t vsmmu_cap = vm->vm_config->vsmmuv2_cap;
	count_t	 num_bound = 0U;

	assert(vsmmu_cap != CSPACE_CAP_INVALID);

	foreach_vector_ptr (device_resource_t, device->iommu_endpoints,
			    iommu_idx, iommu_res) {
		resource_descriptor_t *res = &iommu_res->resource;
		cap_id_t	       iommu_cap =
			get_smmuv2_cap(res->iommu_endpoint.iommu_handle);

		if (iommu_idx >= num_iommu) {
			break;
		}

		assert(iommu_cap != CSPACE_CAP_INVALID);

		gunyah_hyp_viommu_bind_streams_result_t bind_r =
			gunyah_hyp_viommu_bind_streams(
				vsmmu_cap, iommu_cap,
				res->iommu_endpoint.endpoint_id_base,
				res->iommu_endpoint.endpoint_id_count);
		if (bind_r.error != OK) {
			err = bind_r.error;
			LOG_ERR(err);
			if (try_rollback) {
				goto rollback;
			}
			goto out;
		}

		num_bound++;
	}

	err = OK;
	goto out;

rollback:
	rb_err = device_manager_detach_smmu(vm, device, num_bound, false);
	if (rb_err != OK) {
		LOG("device-manager: Detaching SIDs failed during "
		    "rollback: %" PRId32 "\n",
		    (int32_t)rb_err);
		// We now have an inconsistent state and cannot
		// continue.
		panic("rollback failed(detach_smmu)");
	}
out:

	return err;
}

static error_t
device_manager_detach_smmu(vm_t *vm, const device_t *device, count_t num_iommu,
			   bool try_rollback)
{
	error_t		   err, rb_err;
	index_t		   iommu_idx;
	device_resource_t *iommu_res;
	// FIXME: Distinguish between v2 and v3.
	cap_id_t vsmmu_cap   = vm->vm_config->vsmmuv2_cap;
	count_t	 num_unbound = 0U;

	foreach_vector_ptr (device_resource_t, device->iommu_endpoints,
			    iommu_idx, iommu_res) {
		resource_descriptor_t *res = &iommu_res->resource;

		if (iommu_idx >= num_iommu) {
			break;
		}

		gunyah_hyp_viommu_unbind_streams_result_t bind_r =
			gunyah_hyp_viommu_unbind_streams(
				vsmmu_cap, res->iommu_endpoint.endpoint_id_base,
				res->iommu_endpoint.endpoint_id_count);
		if (bind_r.error != OK) {
			err = bind_r.error;
			LOG_ERR(err);
			if (try_rollback) {
				goto rollback;
			}
			goto out;
		}
		num_unbound++;
	}

	err = OK;
	goto out;

rollback:
	rb_err = device_manager_attach_smmu(vm, device, num_unbound, false);
	if (rb_err != OK) {
		LOG("device-manager: Reattaching SIDs failed during "
		    "rollback: %" PRId32 "\n",
		    (int32_t)rb_err);
		// We now have an inconsistent state and cannot
		// continue.
		panic("rollback failed(attach_smmu)");
	}
out:

	return err;
}

static rm_error_t
device_manager_attach_device(vm_t *vm, device_t *device, bool attach_smmu)
{
	rm_error_t	   rm_err;
	error_t		   err;
	index_t		   irq_idx;
	device_resource_t *irq_res;
	count_t		   num_iommu;
	count_t		   irqs_mapped = 0U;

	if (vector_size_ncheck(device->irqs) > 0U) {
		foreach_vector_ptr (device_resource_t, device->irqs, irq_idx,
				    irq_res) {
			uint32_t irq = irq_res->resource.irq.irq_number;

			err = irq_manager_vm_devirq_map(vm, irq, irq, true,
							false);
			if (err != OK) {
				LOG("Failed to map irq %u: %d\n", irq, err);
				rm_err = RM_ERROR_IRQ_INVALID;
				goto err_irq;
			}
			irqs_mapped++;
		}
	}

	if (vector_size_ncheck(device->mmio_regs) > 0U) {
		err = device_manager_map_mmio(vm, device);

		if (err != OK) {
			rm_err = (err == ERROR_NOMEM) ? RM_ERROR_HYP_NOMEM
						      : RM_ERROR_MAP_FAILED;
			goto err_irq;
		}
	}

	num_iommu = vector_size_ncheck(device->iommu_endpoints);
	if (attach_smmu && (num_iommu > 0U)) {
		err = device_manager_attach_smmu(vm, device, num_iommu, true);

		if (err != OK) {
			LOG_ERR(err);
			rm_err = rm_error_from_hyp(err);
			goto err_mmio;
		}
	}

	rm_err = RM_OK;
	goto out;

// Rollback operations in case of an error. If it fails, this is considered
// fatal to avoid continuing with an inconsistent state.
err_mmio:
	err = device_manager_unmap_mmio(vm, device);

	if (err != OK) {
		LOG("device-manager: Detaching MMIOs failed during "
		    "rollback: %" PRId32 "\n",
		    (int32_t)err);
		panic("rollback failed(detach_mmio)");
	}
err_irq:
	foreach_vector_ptr (device_resource_t, device->irqs, irq_idx, irq_res) {
		uint32_t irq = irq_res->resource.irq.irq_number;

		if (irq_idx >= irqs_mapped) {
			break;
		}
		err = irq_manager_vm_devirq_unmap(vm, irq, true, false);
		if (err != OK) {
			LOG("device-manager: Unmap devirq failed during "
			    "rollback: % " PRId32 "\n",
			    (int32_t)err);
			panic("rollback failed(unmap_irq)");
		}
	}
out:

	return rm_err;
}

static rm_error_t
device_manager_detach_device(vm_t *vm, device_t *device)
{
	rm_error_t	   rm_err;
	error_t		   err;
	index_t		   irq_idx;
	device_resource_t *irq_res;
	count_t		   num_iommu;
	count_t		   num_irqs_unmapped = 0U;

	if (vector_size_ncheck(device->irqs) > 0U) {
		foreach_vector_ptr (device_resource_t, device->irqs, irq_idx,
				    irq_res) {
			uint32_t irq = irq_res->resource.irq.irq_number;
			err = irq_manager_vm_devirq_unmap(vm, irq, true, false);

			if (err != OK) {
				rm_err = RM_ERROR_IRQ_INVALID;
				LOG_ERR(rm_err);
				goto err_irq;
			}
			num_irqs_unmapped++;
		}
	}

	if (vector_size_ncheck(device->mmio_regs) > 0U) {
		err = device_manager_unmap_mmio(vm, device);

		if (err != OK) {
			LOG_ERR(err);
			rm_err = rm_error_from_hyp(err);
			goto err_irq;
		}
	}

	num_iommu = vector_size_ncheck(device->iommu_endpoints);
	if (num_iommu > 0U) {
		err = device_manager_detach_smmu(vm, device, num_iommu, true);

		if (err != OK) {
			LOG_ERR(err);
			rm_err = rm_error_from_hyp(err);
			goto err_mmio;
		}
	}

	rm_err = RM_OK;
	goto out;

// Rollback operations in case of an error. If it fails, this is considered
// fatal to avoid continuing with an inconsistent state.
err_mmio:
	err = device_manager_map_mmio(vm, device);

	if (err != OK) {
		LOG("device-manager: Reattaching MMIOs failed during "
		    "rollback: %" PRId32 "\n",
		    (int32_t)err);
		panic("rollback failed(attach_mmio)");
	}
err_irq:
	// Rollback. Try to rebind the already unbound IRQs.

	foreach_vector_ptr (device_resource_t, device->irqs, irq_idx, irq_res) {
		uint32_t irq = irq_res->resource.irq.irq_number;

		if (irq_idx >= num_irqs_unmapped) {
			break;
		}

		err = irq_manager_vm_devirq_map(vm, irq, irq, true, false);
		if (err != OK) {
			LOG("device-manager: Remap IRQ failed during "
			    "rollback: %" PRId32 "\n",
			    (int32_t)err);
			// We now have an inconsistent state and cannot
			// continue.
			panic("rollback failed(map_irq)");
		}
	}
out:

	return rm_err;
}

static rm_error_t
device_manager_device_accept(vmid_t vmid, device_t *device, const bus_t *bus,
			     bool notify)
{
	rm_error_t rm_err, err_detach;
	error_t	   err;
	index_t	   dev_idx;
	vm_t	  *vm	     = vm_lookup(vmid);
	bool	   is_donate = false;
	vmid_t	   orig_owner;

	assert(device != NULL);
	assert(vm != NULL);
	assert(bus != NULL);
	assert(bus->device_handles != NULL);

	is_donate = (device->lend_state == DEVICE_LEND_STATE_OFFERED_DONATE);

	if ((device->lend_state != DEVICE_LEND_STATE_OFFERED_LEND) &&
	    (device->lend_state != DEVICE_LEND_STATE_OFFERED_DONATE)) {
		rm_err = RM_ERROR_DENIED;
		LOG_ERR(rm_err);
		goto out;
	}

	// Check if the device is already attached.
	if (vector_find(bus->device_handles, &check_same_handle,
			&device->handle, &dev_idx)) {
		rm_err = RM_ERROR_DENIED;
		LOG_ERR(rm_err);
		goto out;
	}

	// Reset and Map the device in the VM's space
	// TODO: Flags - bit[0] = Reset the device
	//             - bit[1] = Bind the device to the specified
	//                        Bus handle
	rm_err = device_manager_attach_device(vm, device, true);
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
		goto out;
	}

	orig_owner = device->owner;

	err = vector_push_back(bus->device_handles, device->handle);
	if (err != OK) {
		rm_err = RM_ERROR_NOMEM;
		goto out_detach;
	}

	if (is_donate) {
		device->owner	   = device->borrower;
		device->borrower   = VMID_PEER_DEFAULT;
		device->lend_state = DEVICE_LEND_STATE_NONE;
	} else {
		device->lend_state = DEVICE_LEND_STATE_ACCEPTED;
	}

	if (notify) {
		device_manager_notify_accepted(orig_owner, vmid,
					       device->handle);
	}

	rm_err = RM_OK;

	goto out;

out_detach:
	// Rollback device attachment.

	err_detach = device_manager_detach_device(vm, device);
	if (err_detach != RM_OK) {
		LOG("device-manager: Detach device failed during rollback: "
		    "%" PRId32 "\n",
		    (int32_t)err_detach);
		// We now have an inconsistent state and cannot
		// continue.
		panic("rollback failed(detach_device)");
	}

out:

	return rm_err;
}

static void
device_manager_handle_accept(vmid_t client_id, uint16_t seq_num, void *buf,
			     size_t len)
{
	rm_error_t	       err;
	device_lookup_result_t device_r;
	vm_t		      *vm = vm_lookup(client_id);
	device_accept_req_t   *req;
	device_t	      *device;
	index_t		       bus_idx = 0U;
	bus_t		      *bus;
	device_handle_t	       handle = DEVICE_MGR_INVALID_HANDLE;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len != sizeof(device_accept_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	req = (device_accept_req_t *)buf;
	if ((req->res0[0] | req->res0[1] | req->res0[2]) != 0U) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	handle = req->handle;

	if (!FLAGS_VALID(req->flags, DEVICE_ACCEPT_FLAG)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	device_r = device_manager_handle_lookup(handle);
	if (device_r.device == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		LOG_ERR(err);
		goto out;
	}

	device = device_r.device;
	// FIXME: Use req->bus_handle to select bus if the flag is set
	bus_idx = device_r.bus_index;

	if (client_id != device->borrower) {
		err = RM_ERROR_DENIED;
		LOG_ERR(err);
		goto out;
	}

	// As long as we do not support bridges or switches, only 1 bus per VM
	// needs to be supported. Thus, simply place devices on the same bus
	// index on the borrowing VM, which should be the root copmlex.
	assert(vm->buses != NULL);
	bus = vector_at_ptr(bus_t, vm->buses, bus_idx);
	err = device_manager_device_accept(client_id, device, bus, false);

out:
	LOG("DEVICE_ACCEPT: VM %d: H %#x b %u ret %d\n", client_id, handle,
	    bus_idx, err);
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	rm_standard_reply(client_id, DEVICE_ACCEPT, seq_num, err);
}

static void
device_manager_handle_lend(vmid_t client_id, uint16_t seq_num, void *buf,
			   size_t len)
{
	rm_error_t	       err;
	device_handle_t	       handle	= DEVICE_MGR_INVALID_HANDLE;
	vmid_t		       borrower = VMID_PEER_DEFAULT;
	vm_t		      *vm	= vm_lookup(client_id);
	vm_t		      *borrower_vm;
	device_lend_req_t     *req;
	device_lookup_result_t device_r;
	device_t	      *device;
	index_t		       dev_idx;
	index_t		       bus_idx	      = 0U;
	count_t		       num_irqs_lent  = 0U;
	count_t		       num_mmios_lent = 0U;
	bus_t		      *virtual_bus;
	bool		       found;

	assert(vm != NULL);
	assert(buf != NULL);
	assert(vm->buses != NULL);

	req = (device_lend_req_t *)buf;
	if (len != sizeof(device_lend_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (req->res0[0] != 0U) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (!FLAGS_VALID(req->flags, DEVICE_LEND_FLAG)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	borrower    = req->vmid;
	borrower_vm = vm_lookup(borrower);
	if (borrower_vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	handle	 = req->handle;
	device_r = device_manager_handle_lookup(handle);
	if (device_r.device == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	device	= device_r.device;
	bus_idx = device_r.bus_index;

	if (device->owner != client_id) {
		// TODO: Do we want to prevent leaking information about valid
		// handles?
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (device->lend_state != DEVICE_LEND_STATE_NONE) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	virtual_bus = vector_at_ptr(bus_t, vm->buses, device_r.bus_index);
	assert(virtual_bus != NULL);

	// Check if the device is really attached to this VM.
	found = vector_find(virtual_bus->device_handles, &check_same_handle,
			    &device->handle, &dev_idx);
	if (!found) {
		err = RM_ERROR_DENIED;
		LOG_ERR(err);
		goto out;
	}

	err = device_manager_detach_device(vm, device);
	if (err != RM_OK) {
		LOG_ERR(err);
		goto out;
	}

	device->borrower   = borrower;
	device->lend_state = DEVICE_LEND_STATE_OFFERED_LEND;

	// Remove device from bus's devices.
	vector_delete(virtual_bus->device_handles, dev_idx);
	num_irqs_lent  = vector_size_ncheck(device->irqs);
	num_mmios_lent = vector_size_ncheck(device->mmio_regs);
	err	       = RM_OK;

out:
	LOG("DEVICE_LEND: VM %d to %d: H %#x b: %u #i: %u #m: %u ret %d\n",
	    client_id, borrower, handle, bus_idx, num_irqs_lent, num_mmios_lent,
	    err);

	rm_standard_reply(client_id, DEVICE_LEND, seq_num, err);
}

static rm_error_t
device_manager_device_release(vmid_t vmid, device_t *device, const bus_t *bus,
			      bool notify)
{
	rm_error_t rm_err;
	vm_t	  *vm = vm_lookup(vmid);
	index_t	   dev_idx;
	bool	   found;

	assert(vm != NULL);
	assert(device != NULL);

	// Only lent devices can be released.
	if (device->lend_state != DEVICE_LEND_STATE_ACCEPTED) {
		rm_err = RM_ERROR_DENIED;
		goto out;
	}

	found = vector_find(bus->device_handles, &check_same_handle,
			    &device->handle, &dev_idx);
	if (!found) {
		rm_err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(rm_err);
		goto out;
	}

	// Unmap the device from the borrower. It will only be remapped to the
	// owner when reclaimed.
	rm_err = device_manager_detach_device(vm, device);
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
		goto out;
	}

	// Remove device from bus's devices.
	vector_delete(bus->device_handles, dev_idx);

	device->lend_state = DEVICE_LEND_STATE_OFFERED_RECLAIM;
	device->borrower   = VMID_PEER_DEFAULT;

	if (notify) {
		device_manager_notify_released(device->owner, device->handle);
	}

	rm_err = RM_OK;

out:

	return rm_err;
}

static void
device_manager_handle_release(vmid_t client_id, uint16_t seq_num, void *buf,
			      size_t len)
{
	rm_error_t	       rm_err;
	device_handle_t	       handle = DEVICE_MGR_INVALID_HANDLE;
	device_lookup_result_t device_r;
	vm_t		      *vm = vm_lookup(client_id);
	device_release_req_t  *req;
	device_t	      *device;
	index_t		       bus_idx = 0U;
	bus_t		      *bus;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len != sizeof(device_release_req_t)) {
		rm_err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	req = (device_release_req_t *)buf;
	if ((req->res0[0] | req->res0[1] | req->res0[2]) != 0U) {
		rm_err = RM_ERROR_MSG_INVALID;
		LOG_ERR(rm_err);
		goto out;
	}

	if (!FLAGS_VALID(req->flags, DEVICE_RELEASE_FLAG)) {
		rm_err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	handle	 = req->handle;
	device_r = device_manager_handle_lookup(handle);
	if (device_r.device == NULL) {
		rm_err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	device	= device_r.device;
	bus_idx = device_r.bus_index;

	if (client_id != device->borrower) {
		rm_err = RM_ERROR_DENIED;
		goto out;
	}

	if (device->owner == client_id) {
		rm_err = RM_ERROR_DENIED;
		goto out;
	}

	bus = vector_at_ptr(bus_t, vm->buses, device_r.bus_index);
	assert(bus != NULL);

	rm_err = device_manager_device_release(client_id, device, bus, false);

out:
	LOG("DEVICE_RELEASE: VM %d: H %#x b %u ret %d\n", client_id, handle,
	    bus_idx, rm_err);
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
	}

	rm_standard_reply(client_id, DEVICE_RELEASE, seq_num, rm_err);
}

static rm_error_t
device_manager_device_reclaim(vm_t *vm, device_t *device, const bus_t *bus)
{
	rm_error_t rm_err = RM_OK;
	rm_error_t err_detach;
	error_t	   err;

	assert(vm != NULL);
	assert(device != NULL);
	assert(bus != NULL);

	rm_err = device_manager_attach_device(vm, device, true);
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
		goto out;
	}

	// Re-add the device to the VM's bus
	// TODO: Ensure device is not already present in device_handles.
	err = vector_push_back(bus->device_handles, device->handle);
	if (err != OK) {
		rm_err = RM_ERROR_NOMEM;
		goto out_detach;
	}

	device->borrower   = VMID_PEER_DEFAULT;
	device->lend_state = DEVICE_LEND_STATE_NONE;
	goto out;

out_detach:
	// Rollback device attachment.

	err_detach = device_manager_detach_device(vm, device);
	if (err_detach != RM_OK) {
		LOG("device-manager: Detach device failed during rollback: "
		    "%" PRId32 "\n",
		    (int32_t)err_detach);
		// We now have an inconsistent state and cannot
		// continue.
		panic("rollback failed(detach_device)");
	}

out:
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
	}

	return rm_err;
}

static void
device_manager_handle_reclaim(vmid_t client_id, uint16_t seq_num, void *buf,
			      size_t len)
{
	rm_error_t	       rm_err = RM_OK;
	device_handle_t	       handle = DEVICE_MGR_INVALID_HANDLE;
	device_lookup_result_t device_r;
	vm_t		      *vm = vm_lookup(client_id);
	device_reclaim_req_t  *req;
	device_t	      *device;
	index_t		       bus_idx = 0U;
	bus_t		      *bus;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len != sizeof(device_reclaim_req_t)) {
		rm_err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	req = (device_reclaim_req_t *)buf;
	if ((req->res0[0] | req->res0[1] | req->res0[2]) != 0U) {
		rm_err = RM_ERROR_MSG_INVALID;
		LOG_ERR(rm_err);
		goto out;
	}

	if (!FLAGS_VALID(req->flags, DEVICE_RECLAIM_FLAG)) {
		rm_err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	handle	 = req->handle;
	device_r = device_manager_handle_lookup(handle);
	if (device_r.device == NULL) {
		rm_err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	device	= device_r.device;
	bus_idx = device_r.bus_index;

	if (client_id != device->owner) {
		rm_err = RM_ERROR_DENIED;
		goto out;
	}

	// Only devices which have not been claimed or which have been released
	// can be reclaimed.
	if ((device->lend_state != DEVICE_LEND_STATE_OFFERED_RECLAIM) &&
	    (device->lend_state != DEVICE_LEND_STATE_OFFERED_DONATE) &&
	    (device->lend_state != DEVICE_LEND_STATE_OFFERED_LEND)) {
		rm_err = RM_ERROR_DENIED;
		goto out;
	}

	bus = vector_at_ptr(bus_t, vm->buses, device_r.bus_index);
	assert(bus != NULL);

	// TODO: req->flags - bit[0] - 1: Reset the device (if not already
	// during LEND and/or RELEASE. Map the device in the owner VM.
	rm_err = device_manager_device_reclaim(vm, device, bus);

out:
	LOG("DEVICE_RECLAIM: VM %d: H %#x b %u ret %d\n", client_id, handle,
	    bus_idx, rm_err);
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
	}

	rm_standard_reply(client_id, DEVICE_RECLAIM, seq_num, rm_err);
}

static rm_error_t
device_manager_handle_notify_donated(vmid_t client_id, vmid_t vmid,
				     const device_t *device)
{
	rm_error_t err = RM_OK;

	// Only the owner can donate a device.
	if (device->owner != client_id) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	// Ensure that the device is in donation state
	if (device->lend_state != DEVICE_LEND_STATE_OFFERED_DONATE) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	device_notify_donate_req_t notify = { .owner  = device->owner,
					      .handle = device->handle };

	rm_notify(vmid, NOTIFY_DEVICE_DONATED, &notify, sizeof(notify));
out:
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	return err;
}

static rm_error_t
device_manager_handle_notify_lent(vmid_t client_id, vmid_t vmid,
				  const device_t *device)
{
	rm_error_t err = RM_OK;

	// Only the owner can lend a device
	if (device->owner != client_id) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	// Ensure that the device is in offered state
	if (device->lend_state != DEVICE_LEND_STATE_OFFERED_LEND) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	device_notify_lent_req_t notify = { .owner  = device->owner,
					    .handle = device->handle };

	rm_notify(vmid, NOTIFY_DEVICE_LENT, &notify, sizeof(notify));
out:
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	return err;
}

static void
device_manager_notify_released(vmid_t vmid, device_handle_t handle)
{
	device_notify_release_req_t notify = { .handle = handle };

	rm_notify(vmid, NOTIFY_DEVICE_RELEASED, &notify, sizeof(notify));
}

static rm_error_t
device_manager_handle_notify_released(vmid_t client_id, vmid_t vmid,
				      const device_t *device)
{
	rm_error_t err = RM_OK;

	// Only the borrower can release a device
	if (device->borrower != client_id) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	// Ensure that the device state is offered for reclaim
	if (device->lend_state != DEVICE_LEND_STATE_OFFERED_RECLAIM) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	device_manager_notify_released(vmid, device->handle);

out:
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	return err;
}

static void
device_manager_notify_accepted(vmid_t vmid, vmid_t participant,
			       device_handle_t handle)
{
	device_notify_accept_req_t notify = { .participant = participant,
					      .handle	   = handle };

	rm_notify(vmid, NOTIFY_DEVICE_ACCEPTED, &notify, sizeof(notify));
}

static rm_error_t
device_manager_handle_notify_accepted(vmid_t client_id, vmid_t vmid,
				      const device_t *device)
{
	rm_error_t err = RM_OK;

	// Only the borrower of a lent device and the owner of a donated device
	// can send an ACCEPT notification.
	if (!((device->lend_state == DEVICE_LEND_STATE_ACCEPTED) &&
	      (device->borrower == client_id)) ||
	    ((device->lend_state == DEVICE_LEND_STATE_NONE) &&
	     (device->owner == client_id))) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	device_manager_notify_accepted(vmid, client_id, device->handle);

out:
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	return err;
}

static rm_error_t
device_manager_handle_notify_recall(vmid_t client_id, vmid_t vmid,
				    const device_t *device)
{
	rm_error_t err = RM_OK;

	// Only the owner can recall an accepted device.
	if (device->owner != client_id) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	// Only lent devices can be recalled.
	if (device->lend_state != DEVICE_LEND_STATE_ACCEPTED) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	assert(device->borrower != VMID_PEER_DEFAULT);

	device_notify_recall_req_t notify = { .owner  = device->owner,
					      .handle = device->handle };

	rm_notify(vmid, NOTIFY_DEVICE_RECALL, &notify, sizeof(notify));
out:
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	return err;
}

static rm_error_t
device_manager_notify_by_vmid(uint8_t flags, vmid_t client_id, vmid_t vmid,
			      const device_t *device)
{
	rm_error_t err;

	// Permission checks are done by the individual handlers.

	switch (flags) {
	case DEVICE_NOTIFY_FLAG_DONATED: {
		err = device_manager_handle_notify_donated(client_id, vmid,
							   device);
		break;
	}
	case DEVICE_NOTIFY_FLAG_LENT: {
		err = device_manager_handle_notify_lent(client_id, vmid,
							device);
		break;
	}
	case DEVICE_NOTIFY_FLAG_RELEASED: {
		err = device_manager_handle_notify_released(client_id, vmid,
							    device);
		break;
	}
	case DEVICE_NOTIFY_FLAG_ACCEPTED: {
		err = device_manager_handle_notify_accepted(client_id, vmid,
							    device);
		break;
	}
	case DEVICE_NOTIFY_FLAG_RECALL: {
		err = device_manager_handle_notify_recall(client_id, vmid,
							  device);
		break;
	}
	default:
		err = RM_ERROR_ARGUMENT_INVALID;
		break;
	}

	return err;
}

static void
device_manager_handle_notify(vmid_t client_id, uint16_t seq_num, void *buf,
			     size_t len)
{
	rm_error_t	       err    = RM_OK;
	device_handle_t	       handle = DEVICE_MGR_INVALID_HANDLE;
	vm_t		      *vm     = vm_lookup(client_id);
	device_notify_req_t   *req;
	device_lookup_result_t device_r;
	device_t	      *device;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len < sizeof(device_notify_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	req = (device_notify_req_t *)buf;
	if (req->res0[0] != 0U) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (!FLAGS_VALID(req->flags, DEVICE_NOTIFY_FLAG)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	handle	 = req->handle;
	device_r = device_manager_handle_lookup(handle);
	if (device_r.device == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}
	device = device_r.device;

	// Note: the flags are treated as mutually exclusive, as only one
	// operation can be applied to a device at a time (e.g. a device cannot
	// be lent and released simultaneously).
	if (compiler_popcount((uint32_t)req->flags) != 1U) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if ((req->flags &
	     (DEVICE_NOTIFY_FLAG_DONATED | DEVICE_NOTIFY_FLAG_LENT |
	      DEVICE_NOTIFY_FLAG_RECALL)) != 0U) {
		// Notification requested for specified VMID
		if ((req->req_vmid == 0U) ||
		    (vm_lookup(req->req_vmid) == NULL)) {
			err = RM_ERROR_ARGUMENT_INVALID;
			LOG_ERR(err);
			goto out;
		}

		err = device_manager_notify_by_vmid(req->flags, client_id,
						    req->req_vmid, device);
		if (err != RM_OK) {
			LOG_ERR(err);
			goto out;
		}
	} else if (req->req_vmid != 0U) {
		// Notifications for specific VMIDs can only be requested for
		// devices that have been lent, donated or recalled.

		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
	} else {
		// Notification requested for self.

		err = device_manager_notify_by_vmid(req->flags, client_id,
						    device->owner, device);
	}

out:
	LOG("DEVICE_NOTIFY: VM %d: H %#x ret %d\n", client_id, handle, err);

	if (err != RM_OK) {
		LOG_ERR(err);
	}

	rm_standard_reply(client_id, DEVICE_NOTIFY, seq_num, err);
}

static void
device_manager_handle_find_handle(vmid_t client_id, uint16_t seq_num, void *buf,
				  size_t len)
{
	rm_error_t		  err;
	vm_t			 *vm = vm_lookup(client_id);
	vector_t		 *buses;
	index_t			  bus_idx, dev_idx, res_idx;
	device_t		 *device;
	host_bus_t		 *bus;
	device_handle_t		  handle = DEVICE_MGR_INVALID_HANDLE;
	device_find_handle_req_t *req;
	resource_descr_type_t	  rtype;
	device_resource_t	 *res;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len != sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	req   = (device_find_handle_req_t *)buf;
	rtype = (resource_descr_type_t)req->type_selector.type;
	buses = host_buses;

	foreach_vector_ptr (host_bus_t, buses, bus_idx, bus) {
		assert(bus->devices != NULL);

		foreach_vector_ptr (device_t, bus->devices, dev_idx, device) {
			vector_t *search_vector = NULL;

			switch (rtype) {
			case RESOURCE_DESCR_TYPE_MMIO:
				search_vector = device->mmio_regs;
				break;
			case RESOURCE_DESCR_TYPE_IRQ:
				search_vector = device->irqs;
				break;
			case RESOURCE_DESCR_TYPE_IOMMU:
				search_vector = device->iommu_endpoints;
				break;
			case RESOURCE_DESCR_TYPE_MSI:
				search_vector = device->msi_endpoints;
				break;
			case RESOURCE_DESCR_TYPE_PCIE:
				search_vector = device->pcie_functions;
				break;
			default:
				err = RM_ERROR_ARGUMENT_INVALID;
				goto out;
			}

			if (search_vector == NULL) {
				// Device does not have this type of resources
				continue;
			}

			foreach_vector_ptr (device_resource_t, search_vector,
					    res_idx, res) {
				if (!CMP_DESCR(res, req)) {
					continue;
				}
				if ((device->owner != client_id) &&
				    (device->borrower != client_id)) {
					err = RM_ERROR_DENIED;
					goto out;
				}

				handle = device->handle;
				if (handle == DEVICE_MGR_INVALID_HANDLE) {
					err = RM_ERROR_ARGUMENT_INVALID;
					goto out;
				}
				break;
			}

			if (handle != DEVICE_MGR_INVALID_HANDLE) {
				// A valid handle has been found, return it.
				err = RM_OK;
				goto out;
			}
		}
	}

	// No matching device found.
	err = RM_ERROR_LOOKUP_FAILED;

out:
	LOG("DEVICE_FIND_HANDLE: VM %d: H %#x ret %d\n", client_id, handle,
	    err);
	if (err != RM_OK) {
		LOG_ERR(err);
		rm_standard_reply(client_id, DEVICE_FIND_HANDLE, seq_num, err);
	} else {
		device_find_handle_reply_t reply = {
			.handle = handle,
		};
		rm_reply(client_id, DEVICE_FIND_HANDLE, seq_num, &reply,
			 sizeof(reply));
	}
}

static void
device_manager_handle_get_resources(vmid_t client_id, uint16_t seq_num,
				    void *buf, size_t len)
{
	rm_error_t			err    = RM_OK;
	device_handle_t			handle = DEVICE_MGR_INVALID_HANDLE;
	vm_t			       *vm     = vm_lookup(client_id);
	device_get_resources_req_t     *req;
	device_lookup_result_t		device_r;
	device_t		       *device;
	count_result_t			res_cnt_r;
	size_t				reply_header_size;
	size_t				reply_body_size;
	size_t				reply_size = 0U;
	uint32_t		       *reply	   = NULL;
	device_get_resources_rep_hdr_t *reply_header;
	resource_descriptor_t	       *reply_body;
	device_resource_t	       *res;
	index_t				i;
	index_t				res_idx = 0U;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len != sizeof(device_get_resources_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	req = (device_get_resources_req_t *)buf;
	if ((req->res0[0] | req->res0[1] | req->res0[2]) != 0U) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (!FLAGS_VALID(req->flags, DEVICE_GET_RESOURCES_FLAG)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	handle = req->handle;

	// Handle req->flags.
	// TODO: Flags bit[0] - 1 = Return the device's physical resources,
	// rather than virtual.

	device_r = device_manager_handle_lookup(handle);
	if (device_r.device == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		LOG_ERR(err);
		goto out;
	}
	device = device_r.device;

	if (device->owner != client_id) {
		err = RM_ERROR_DENIED;
		LOG_ERR(err);
		goto out;
	}

	res_cnt_r = device_get_resource_count(device);
	if (res_cnt_r.e != OK) {
		err = RM_ERROR_NOMEM;
		LOG_ERR(err);
		goto out;
	}

	if (util_mult_integer_overflows(res_cnt_r.r,
					sizeof(resource_descriptor_t))) {
		err = RM_ERROR_NOMEM;
		LOG_ERR(err);
		goto out;
	}
	reply_body_size = res_cnt_r.r * sizeof(resource_descriptor_t);

	reply_header_size = sizeof(device_get_resources_rep_hdr_t);
	if (util_add_overflows(reply_header_size, reply_body_size)) {
		err = RM_ERROR_NOMEM;
		LOG_ERR(err);
		goto out;
	}
	reply_size = reply_header_size + reply_body_size;

	reply = (uint32_t *)malloc(reply_size);
	if (reply == NULL) {
		err = RM_ERROR_NOMEM;
		LOG_ERR(err);
		goto out;
	}

	(void)memset(reply, 0, reply_size);
	reply_header = (device_get_resources_rep_hdr_t *)(uintptr_t)reply;
	reply_body   = (resource_descriptor_t *)((uintptr_t)&reply_header[1]);

	if (util_add_overflows(reply_header->num_entries, res_cnt_r.r)) {
		err = RM_ERROR_NOMEM;
		LOG_ERR(err);
		goto out;
	}

	reply_header->num_entries = (uint16_t)res_cnt_r.r;

	for (i = 0U; i < vector_size_ncheck(device->mmio_regs); i++) {
		res = vector_at_ptr(device_resource_t, device->mmio_regs, i);
		assert(res != NULL);
		reply_body[res_idx++] = res->resource;
	}

	for (i = 0U; i < vector_size_ncheck(device->irqs); i++) {
		res = vector_at_ptr(device_resource_t, device->irqs, i);
		assert(res != NULL);
		reply_body[res_idx++] = res->resource;
	}

	for (i = 0U; i < vector_size_ncheck(device->iommu_endpoints); i++) {
		res = vector_at_ptr(device_resource_t, device->iommu_endpoints,
				    i);
		assert(res != NULL);
		reply_body[res_idx++] = res->resource;
	}

	for (i = 0U; i < vector_size_ncheck(device->msi_endpoints); i++) {
		res = vector_at_ptr(device_resource_t, device->msi_endpoints,
				    i);
		assert(res != NULL);
		reply_body[res_idx++] = res->resource;
	}

	for (i = 0U; i < vector_size_ncheck(device->pcie_functions); i++) {
		res = vector_at_ptr(device_resource_t, device->pcie_functions,
				    i);
		assert(res != NULL);
		reply_body[res_idx++] = res->resource;
	}

out:
	LOG("DEVICE_GET_RESOURCES: VM %d: H %#x ret %d\n", client_id, handle,
	    err);
	if (err == RM_OK) {
		rm_reply(client_id, DEVICE_GET_RESOURCES, seq_num, reply,
			 reply_size);
	} else {
		LOG_ERR(err);
		rm_standard_reply(client_id, DEVICE_GET_RESOURCES, seq_num,
				  err);
	}

	if (reply != NULL) {
		free(reply);
	}
}

static rm_error_t
device_manager_map_and_scan_pcie_bus(vm_t *vm, host_bus_t *bus)
{
	rm_error_t err;

	// TODO: Map the PCIe Configuration Space from the host VM.
	(void)vm;

	// lockdown the bus, initiate scanning mode
	// Following is applicable:
	// * ECAM aperture is fully read-only to the ownerVM
	// * The write attempting vCPU to ECAM will be blocked
	//   until the state is transitioned.
	// * Any vCPU access to a Memory (behind PCI) aperture
	//   may be trapped and briefly blocked in order to serialize
	//   it against BAR probes.
	// * Derived PCIe function objects may be created and activated
	//   but passthrough cannot be enabled.

	assert(bus != NULL);
	assert(bus->pci_host != NULL);

	err = pcie_scan_bus(bus->pci_host->cfg_space,
			    &bus->pci_host->pci_functions);

	if (err != RM_OK) {
		goto out;
	}
out:
	return err;
}

static void
device_manager_handle_bus_lockdown(vmid_t client_id, uint16_t seq_num,
				   void *buf, size_t len)
{
	rm_error_t		 err;
	host_bus_lookup_result_t bus_lookup_r;
	vm_t			*vm	= vm_lookup(client_id);
	device_handle_t		 handle = *(device_handle_t *)buf;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len != sizeof(device_bus_lockdown_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}

	bus_lookup_r = device_manager_bus_handle_lookup(handle);
	if (bus_lookup_r.err != OK) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}

	err = device_manager_map_and_scan_pcie_bus(vm, bus_lookup_r.bus);
	// TODO: Once scanning is complete, transition to Restrictred State.

out_err:
	LOG("DEVICE_BUS_LOCKDOWN: VM %d: H %#x ret %d\n", client_id, handle,
	    err);
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	rm_standard_reply(client_id, DEVICE_BUS_LOCKDOWN, seq_num, err);
}

static void
device_manager_handle_bus_unlock(vmid_t client_id, uint16_t seq_num, void *buf,
				 size_t len)
{
	rm_error_t		 err;
	host_bus_lookup_result_t bus_lookup_r;
	vm_t			*vm = vm_lookup(client_id);

	device_handle_t handle = *(device_handle_t *)buf;

	assert(vm != NULL);
	assert(buf != NULL);

	if (len != sizeof(device_bus_unlock_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}

	bus_lookup_r = device_manager_bus_handle_lookup(handle);
	if (bus_lookup_r.err != OK) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}

	// TODO: Ensure that there no devices on the bus that are
	// lent and/or donated. Otherwise, deny the bus unlock.
	err = RM_ERROR_UNIMPLEMENTED;

out_err:
	LOG("DEVICE_BUS_UNLOCK: VM %d: H %#x ret %d\n", client_id, handle, err);
	if (err != RM_OK) {
		LOG_ERR(err);
	}

	rm_standard_reply(client_id, DEVICE_BUS_UNLOCK, seq_num, err);
}

static void
device_manager_handle_donate(vmid_t client_id, uint16_t seq_num, void *buf,
			     size_t len)
{
	rm_error_t	       err = RM_OK;
	device_lookup_result_t device_r;
	vmid_t		       recipient = VMID_PEER_DEFAULT;
	device_handle_t	       handle	 = DEVICE_MGR_INVALID_HANDLE;
	vm_t		      *vm	 = vm_lookup(client_id);
	device_donate_req_t   *req;
	device_t	      *device;
	index_t		       dev_idx;
	index_t		       bus_idx		 = 0U;
	count_t		       num_irqs_donated	 = 0U;
	count_t		       num_mmios_donated = 0U;
	bus_t		      *virtual_bus;
	bool		       found;

	assert(vm != NULL);
	assert(buf != NULL);

	req = (device_donate_req_t *)buf;
	if (len != sizeof(device_donate_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (req->res0[0] != 0U) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (!FLAGS_VALID(req->flags, DEVICE_DONATE_FLAG)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	recipient = req->vmid;
	handle	  = req->handle;

	if (vm_lookup(recipient) == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	device_r = device_manager_handle_lookup(handle);
	if (device_r.device == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}
	device	= device_r.device;
	bus_idx = device_r.bus_index;

	if (device->lend_state != DEVICE_LEND_STATE_NONE) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (client_id != device->owner) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	err = device_manager_detach_device(vm, device);
	if (err != RM_OK) {
		LOG_ERR(err);
		goto out;
	}

	device->borrower   = recipient;
	device->lend_state = DEVICE_LEND_STATE_OFFERED_DONATE;

	// Remove device from bus's devices.
	virtual_bus = vector_at_ptr(bus_t, vm->buses, device_r.bus_index);
	assert(virtual_bus != NULL);

	found = vector_find(virtual_bus->device_handles, &check_same_handle,
			    &device->handle, &dev_idx);
	assert(found);

	vector_delete(virtual_bus->device_handles, dev_idx);
	num_irqs_donated  = vector_size_ncheck(device->irqs);
	num_mmios_donated = vector_size_ncheck(device->mmio_regs);
	err		  = RM_OK;
	goto out;

out:
	LOG("DEVICE_DONATE: VM %d to %d: H %#x b %u #i %u #m %u ret %d\n",
	    client_id, recipient, handle, bus_idx, num_irqs_donated,
	    num_mmios_donated, err);

	rm_standard_reply(client_id, DEVICE_DONATE, seq_num, err);
}

// Bus management

static bus_add_result_t
device_manager_add_virtual_bus(const vm_t *vm)
{
	error_t		 err;
	vector_t	*buses;
	uint64_result_t	 seed;
	uint32_t	 rnd, handle;
	bus_t		 bus;
	index_t		 bus_index;
	bus_add_result_t res = { .index = 0U };

	assert(vm != NULL);
	assert(vm->buses != NULL);

	buses = vm->buses;

	// Randomized bus handle based on the bus index. This is just to make
	// handles somewhat unpredictable without any strict requirements on
	// entropy.
	seed = random_get_entropy64();
	if (seed.e != OK) {
		res.err = seed.e;
		goto out;
	}

	bus_index = vector_size(buses);
	rnd	  = (uint32_t)seed.r % 1024U;

	if (util_mult_integer_overflows(bus_index, 1024U)) {
		res.err = ERROR_NORESOURCES;
		goto out;
	}
	handle = bus_index * 1024U;

	if (util_add_overflows(handle, rnd)) {
		res.err = ERROR_NORESOURCES;
		goto out;
	}
	bus.handle = handle + rnd;

	bus.device_handles = vector_init(device_handle_t, 4U, 4U);
	if (bus.device_handles == NULL) {
		res.err = ERROR_NOMEM;
		goto out;
	}

	err = vector_push_back(buses, bus);
	if (err != OK) {
		res.err = err;
		goto err_free;
	}

	res.index = vector_size(buses) - 1U;
	res.err	  = OK;
	goto out;

err_free:
	vector_free(&bus.device_handles);
out:

	return res;
}

static bus_add_result_t
device_manager_add_physical_bus(pci_host_t *pci_host)
{
	error_t		 err;
	uint64_result_t	 seed;
	host_bus_t	 bus;
	static uint32_t	 prev_base = 0U;
	uint32_t	 rand_offset;
	bus_add_result_t res = { .index = 0U };

	assert(host_buses != NULL);

	// Device handle random base allocation.
	//
	// Make device handles globally unique by ensuring that no device
	// handle range overlaps with the handle range of another bus.  We have
	// to place the start of the new bus's handle segment behind the
	// previously allocated bus's segment. It is assumed that buses are not
	// removed individually from VMs, that they are removed all at once by
	// device_manager_deinit_vm() and that VMs are not reallocated
	// frequently. If this changes, a scheme for reusing ranges has to be
	// introduced.
	seed = random_get_entropy64();
	if (seed.e != OK) {
		res.err = seed.e;
		goto out;
	}

	// This bus's device handle segment should be placed behind the previous
	// bus's segment with a random offset with a ceiling that is limited to
	// DEVICE_HANDLE_MAX_SEGMENT_OFFS to ensure that a sufficiently large
	// number segments can be allocated from 32-bit space. It is currently
	// assumed that 128K buses should be enough for everybody.
	rand_offset = ((uint32_t)seed.r % (DEVICE_HANDLE_MAX_SEGMENT_OFFS -
					   DEVICES_PER_BUS_MAX + 1U)) +
		      DEVICES_PER_BUS_MAX;

	// Make sure there is room.
	if (util_add_overflows(prev_base, rand_offset)) {
		res.err = ERROR_NORESOURCES;
		goto out;
	}

	bus.rand_base = prev_base + rand_offset;
	if (util_add_overflows(bus.rand_base, DEVICES_PER_BUS_MAX)) {
		res.err = ERROR_NOMEM;
		goto out;
	}

	// Since device handles and bus handles are distinct, we can re-use
	// the random device handle base as bus handle. This may be subject
	// to future changes, which is why this is stored in a separate
	// struct member.
	bus.handle = bus.rand_base;

	bus.devices = vector_init(device_t, 4U, 4U);
	if (bus.devices == NULL) {
		res.err = ERROR_NOMEM;
		goto out;
	}

	// Holds the Root Complex info linked with this bus
	bus.pci_host = pci_host;

	err = vector_push_back(host_buses, bus);
	if (err != OK) {
		res.err = err;
		goto err_free;
	}

	prev_base = bus.rand_base;
	res.index = vector_size(host_buses) - 1U;
	res.err	  = OK;
	goto out;

err_free:
	vector_free(&bus.devices);
out:

	return res;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

// Removes MMIO ranges from global MMIO range list and donates each range back
// to the HLOS.
static void
rollback_mem_donation(device_t *device, count_t num_mmios, count_t num_ranges)
{
	error_t		   err;
	vm_t		  *hlos = vm_lookup(VMID_HLOS);
	device_resource_t *mmio_res;
	index_t		   mmio_idx;

	vm_memory_batch_start(device->me_cap);

	foreach_vector_ptr (device_resource_t, device->mmio_regs, mmio_idx,
			    mmio_res) {
		size_t			psize;
		paddr_t			paddr;
		range_list_find_ret_t	find_r;
		range_list_remove_ret_t list_r;

		// Check if we exceed the number of allocated ranges.
		if (mmio_idx >= num_ranges) {
			break;
		}

		paddr = ((paddr_t)mmio_res->resource.mmio_reg.base_addr_hi
			 << 32U) |
			(paddr_t)mmio_res->resource.mmio_reg.base_addr_lo;
		psize = (size_t)mmio_res->resource.mmio_reg.size;

		// Before we can remove the range, we have to set its data to
		// INVALID_DATA.
		find_r = range_list_find_range(mmio_ranges, paddr, psize,
					       PAGE_SIZE);
		if (find_r.err != OK) {
			err = find_r.err;
			LOG_ERR(err);
			goto out;
		}

		err = range_list_update(mmio_ranges, paddr, psize,
					find_r.selected_range, INVALID_DATA);
		if (err != OK) {
			LOG_ERR(err);
			goto out;
		}

		list_r = range_list_remove(mmio_ranges, paddr, psize, PAGE_SIZE,
					   INVALID_DATA);
		if (list_r.err != OK) {
			err = list_r.err;
			LOG_ERR(err);
			goto out;
		}

		// Check if we exceed the number of MMIO donations.
		if (mmio_idx >= num_mmios) {
			break;
		}

		// Donate memory back to the HLOS device extent.
		err = vm_memory_donate_extent(hlos, MEM_TYPE_IO, NULL,
					      device->me_cap, paddr, psize,
					      false);
		if (err != OK) {
			LOG_ERR(err);
			goto out;
		}
	}

	err = OK;

out:
	vm_memory_batch_end();
	if (err != OK) {
		LOG("device-manager: Add mmio failed during rollback:"
		    "%" PRId32 "\n",
		    (int32_t)err);
		// We now have an inconsistent state and cannot continue.
		panic("rollback failed(rollback_mem_donation)");
	}
}

// Donates device memory from the HLOS device extent to the new device's
// extent.
static error_t
device_add_memory(device_t *device)
{
	error_t		   err;
	vm_t		  *hlos = vm_lookup(VMID_HLOS);
	device_resource_t *mmio_res;
	index_t		   mmio_idx;
	count_t		   num_mmios_donated   = 0U;
	count_t		   num_ranges_inserted = 0U;

	assert(hlos != NULL);

	vm_memory_batch_start(device->me_cap);

	foreach_vector_ptr (device_resource_t, device->mmio_regs, mmio_idx,
			    mmio_res) {
		size_t	psize;
		paddr_t paddr;

		paddr = ((paddr_t)mmio_res->resource.mmio_reg.base_addr_hi
			 << 32U) |
			(paddr_t)mmio_res->resource.mmio_reg.base_addr_lo;
		psize = (size_t)mmio_res->resource.mmio_reg.size;

		err = insert_device_range(device, paddr, psize);
		if (err != OK) {
			LOG_ERR(err);
			goto out_rollback;
		}
		num_ranges_inserted++;

		err = vm_memory_donate_extent(hlos, MEM_TYPE_IO, NULL,
					      device->me_cap, paddr, psize,
					      true);
		if (err != OK) {
			LOG_ERR(err);
			goto out_rollback;
		}
		num_mmios_donated++;
	}

	vm_memory_batch_end();
	err = OK;
	goto out;

out_rollback:
	vm_memory_batch_end();
	rollback_mem_donation(device, num_mmios_donated, num_ranges_inserted);
out:

	return err;
}

// Remaps IRQs back to the HLOS in case of an error.
static void
rollback_irqs(device_t *device, count_t num_irqs)
{
	error_t		   err;
	vm_t		  *hlos = vm_lookup(VMID_HLOS);
	index_t		   irq_idx;
	device_resource_t *irq_res;

	foreach_vector_ptr (device_resource_t, device->irqs, irq_idx, irq_res) {
		index_t irq = irq_res->resource.irq.irq_number;

		if (irq_idx >= num_irqs) {
			break;
		}

		err = irq_manager_vm_hwirq_map(hlos, irq, irq, true);
		if (err != OK) {
			goto out;
		}
	}

	err = OK;

out:
	if (err != OK) {
		LOG("device-manager: Remapping IRQs failed during rollback:"
		    "%" PRId32 "\n",
		    (int32_t)err);
		// We now have an inconsistent state and cannot continue.
		panic("rollback failed(rollback_irq)");
	}
}

// Unmaps IRQs from the HLOS so that they can be mapped as part of a device.
static error_t
device_add_irqs(device_t *device)
{
	error_t		   err;
	vm_t		  *hlos = vm_lookup(VMID_HLOS);
	index_t		   irq_idx;
	device_resource_t *irq_res;
	count_t		   num_irqs_unmapped = 0U;

	assert(hlos != NULL);

	foreach_vector_ptr (device_resource_t, device->irqs, irq_idx, irq_res) {
		index_t	      irq = irq_res->resource.irq.irq_number;
		vmid_result_t vmid_r;

		assert(arch_irq_cpulocal_valid(irq) ||
		       arch_irq_global_valid(irq));

		vmid_r = irq_manager_hwirq_get_owner(irq);
		if (vmid_r.e != OK) {
			err = vmid_r.e;
			LOG_ERR(err);
			goto out;
		}

		if (vmid_r.r != VMID_HLOS) {
			err = irq_manager_hwirq_donate(irq, vmid_r.r,
						       VMID_HLOS);
			if (err != OK) {
				LOG("Failed to remap passthrough irq %u to HLOS",
				    irq);
				goto out;
			}
		} else {
			// By default, all IRQs are mapped to the HLOS as type
			// IRQ_TYPE_HW, This mapping must be removed before
			// they can be mapped to the HLOS as IRQ_TYPE_DEV by
			// device_manager_attach_device.
			err = irq_manager_vm_hwirq_unmap(hlos, irq, true);
			if (err != OK) {
				LOG_ERR(err);
				goto out;
			}
		}

		num_irqs_unmapped++;
	}

	err = OK;

out:
	if (err != OK) {
		rollback_irqs(device, num_irqs_unmapped);
	}

	return err;
}

// Detaches  SIDs from the HLOS so that they can be mapped as part of a device.
static error_t
device_add_iommu_eps(device_t *device)
{
	error_t		   err = OK;
	index_t		   iommu_idx;
	device_resource_t *iommu_res;
	vm_t		  *hlos = vm_lookup(VMID_HLOS);
	cap_id_t	   vsmmu_cap;

	assert(hlos != NULL);

	// Perform a dummy bind on the HLOS using count == 0 to to associate
	// the physical address with the virtual SMMU so that the first unbind
	// operation can succeed.
	vsmmu_cap = hlos->vm_config->vsmmuv2_cap;
	foreach_vector_ptr (device_resource_t, device->iommu_endpoints,
			    iommu_idx, iommu_res) {
		resource_descriptor_t *res = &iommu_res->resource;
		cap_id_t	       iommu_cap =
			get_smmuv2_cap(res->iommu_endpoint.iommu_handle);
		gunyah_hyp_viommu_bind_streams_result_t bind_r;

		bind_r = gunyah_hyp_viommu_bind_streams(vsmmu_cap, iommu_cap, 0,
							0U);
		if (bind_r.error != OK) {
			err = bind_r.error;
			LOG_ERR(err);
			break;
		}
	}

	return err;
}

static error_t
device_manager_host_bus_add_device(index_t bus_idx, vector_t *mmio_regs,
				   vector_t *irqs, vector_t *iommu_endpoints,
				   vector_t *msi_endpoints,
				   vector_t *pcie_functions, vmid_t owner)
{
	error_t		err;
	index_t		dev_idx;
	cap_id_result_t cap_ret;
	host_bus_t     *bus;
	device_t	device;
	count_t		num_mmios, num_irqs, num_iommu_eps;

	assert(host_buses != NULL);

	bus = vector_at_ptr(host_bus_t, host_buses, bus_idx);

	assert(bus != NULL);
	assert(bus->devices != NULL);

	dev_idx		       = vector_size(bus->devices);
	device.owner	       = owner;
	device.borrower	       = VMID_PEER_DEFAULT;
	device.lend_state      = DEVICE_LEND_STATE_NONE;
	device.mmio_regs       = mmio_regs;
	device.irqs	       = irqs;
	device.iommu_endpoints = iommu_endpoints;
	device.msi_endpoints   = msi_endpoints;
	device.pcie_functions  = pcie_functions;
	device.handle	       = device_manager_handle_alloc(bus, dev_idx);

	if (device.handle == DEVICE_MGR_INVALID_HANDLE) {
		err = ERROR_NORESOURCES;
		LOG_ERR(err);
		goto out;
	}

	num_mmios     = vector_size_ncheck(mmio_regs);
	num_irqs      = vector_size_ncheck(irqs);
	num_iommu_eps = vector_size_ncheck(iommu_endpoints);

	if (num_mmios > 0U) {
		// Create device memory extent, derived from the HLOS device
		// memory extent.
		cap_ret = vm_memory_create_extent(MEM_TYPE_IO);
		if (cap_ret.e != OK) {
			err = cap_ret.e;
			LOG_ERR(err);
			goto out;
		}
		device.me_cap = cap_ret.r;

		err = device_add_memory(&device);
		if (err != OK) {
			LOG_ERR(err);
			goto out;
		}
	} else {
		device.me_cap = CSPACE_CAP_INVALID;
	}

	if (num_irqs > 0U) {
		err = device_add_irqs(&device);
		if (err != OK) {
			LOG_ERR(err);
			goto out_rollback_mmios;
		}
	}

	if (num_iommu_eps > 0U) {
		err = device_add_iommu_eps(&device);
		if (err != OK) {
			LOG_ERR(err);
			goto out_rollback_irqs;
		}
	}

	err = vector_push_back(bus->devices, device);
	if (err != OK) {
		// There is no way to undo the dummy bind on the SMMU SIDs,
		// so just go straight to the IRQ rollback.
		goto out_rollback_irqs;
	}

	goto out;

out_rollback_irqs:
	if (num_irqs > 0U) {
		rollback_irqs(&device, num_irqs);
	}
out_rollback_mmios:
	if (num_mmios > 0U) {
		rollback_mem_donation(&device, num_mmios, num_mmios);
	}
out:

	return err;
}

static error_t
device_manager_virt_bus_add_device(const bus_t *bus, device_t *device,
				   vmid_t owner, bool attach_smmu)
{
	error_t	   err;
	rm_error_t rm_err;
	vm_t	  *owner_vm = vm_lookup(owner);

	assert(owner_vm != NULL);
	assert(bus != NULL);
	assert(bus->device_handles != NULL);

	rm_err = device_manager_attach_device(owner_vm, device, attach_smmu);
	if (rm_err != RM_OK) {
		LOG("device-manager: Failed to attach device %" PRId32 "\n",
		    (int32_t)rm_err);

		err = ERROR_DENIED;
		goto out;
	}

	device->owner = owner;
	err	      = vector_push_back(bus->device_handles, device->handle);
	if (err != OK) {
		LOG_ERR(err);
		goto out_detach;
	}

	goto out;

out_detach:
	// Rollback device attachment.

	rm_err = device_manager_detach_device(owner_vm, device);
	if (rm_err != RM_OK) {
		LOG("device-manager: Detach device failed during rollback: "
		    "%" PRId32 "\n",
		    (int32_t)rm_err);
		// We now have an inconsistent state and cannot
		// continue.
		panic("rollback failed(detach_device)");
	}

out:

	return err;
}

static error_t
device_manager_virt_bus_remove_device(const bus_t *bus, index_t dev_idx,
				      vmid_t vmid, bool detach)
{
	error_t		       err;
	device_handle_t	      *handle;
	device_lookup_result_t device_r;
	device_t	      *device;
	vm_t		      *vm = vm_lookup(vmid);

	assert(bus != NULL);
	assert(bus->device_handles != NULL);
	assert(vm != NULL);

	handle = vector_at_ptr(device_handle_t, bus->device_handles, dev_idx);
	if (handle == NULL) {
		err = ERROR_NORESOURCES;
		LOG_ERR(err);
		goto out;
	}

	device_r = device_manager_handle_lookup(*handle);
	if (device_r.device == NULL) {
		err = ERROR_NORESOURCES;
		LOG_ERR(err);
		goto out;
	}
	device = device_r.device;

	if (detach) {
		rm_error_t rm_err = device_manager_detach_device(vm, device);
		if (rm_err != RM_OK) {
			LOG("device-manager: Failed to detach device %" PRId32
			    "\n",
			    (int32_t)rm_err);

			err = ERROR_DENIED;
			goto out;
		}
	}

	device->owner	   = VMID_PEER_DEFAULT;
	device->borrower   = VMID_PEER_DEFAULT;
	device->lend_state = DEVICE_LEND_STATE_NONE;

	// Remove device from bus's devices.
	vector_delete(bus->device_handles, dev_idx);
	err = OK;
out:

	return err;
}

static error_t
add_dev_resources(const platform_device_t *device, vector_t **res,
		  resource_descr_type_t res_type)
{
	error_t err;
	index_t idx;
	count_t num_res;

	assert(device != NULL);
	assert(res != NULL);

	num_res = platform_get_device_res_count(device, res_type);
	*res	= vector_init(device_resource_t, 1U, 1U);
	if (*res == NULL) {
		err = ERROR_NOMEM;
		LOG_ERR(err);
		goto out;
	}

	for (idx = 0; idx < num_res; idx++) {
		const resource_descriptor_t *rd =
			platform_get_device_res(device, idx, res_type);
		device_resource_t dr = { .capid = CSPACE_CAP_INVALID };

		assert(rd != NULL);

		dr.resource = *rd;
		err	    = vector_push_back(*res, dr);
		if (err != OK) {
			LOG_ERR(err);
			vector_free(res);
			goto out;
		}
	}

	err = OK;

out:

	return err;
}

static error_t
device_manager_add_platform_devices(index_t bus_idx)
{
	error_t	  err = OK;
	index_t	  dev_idx;
	vector_t *mmios		  = NULL;
	vector_t *irqs		  = NULL;
	vector_t *iommu_endpoints = NULL;

	for (dev_idx = 0; dev_idx < platform_get_device_count(); dev_idx++) {
		const platform_device_t *device = platform_get_device(dev_idx);

		assert(device != NULL);

		err = add_dev_resources(device, &mmios,
					RESOURCE_DESCR_TYPE_MMIO);
		if (err != OK) {
			goto out;
		}

		err = add_dev_resources(device, &irqs, RESOURCE_DESCR_TYPE_IRQ);
		if (err != OK) {
			goto out_free_mmios;
		}

		err = add_dev_resources(device, &iommu_endpoints,
					RESOURCE_DESCR_TYPE_IOMMU);
		if (err != OK) {
			goto out_free_irqs;
		}

		err = device_manager_host_bus_add_device(bus_idx, mmios, irqs,
							 iommu_endpoints, NULL,
							 NULL,
							 VMID_PEER_DEFAULT);
		if (err != OK) {
			goto out_free_iommu;
		}
	}

	goto out;

out_free_iommu:
	if (iommu_endpoints != NULL) {
		vector_free(&iommu_endpoints);
	}
out_free_irqs:
	if (irqs != NULL) {
		vector_free(&irqs);
	}
out_free_mmios:
	if (mmios != NULL) {
		vector_free(&mmios);
	}
out:

	return err;
}

#pragma clang diagnostic pop

// Initialization and de-initialization

static void
device_manager_free_device(device_t *device)
{
	assert(device != NULL);

	vector_free(&device->mmio_regs);
	vector_free(&device->irqs);
	vector_free(&device->iommu_endpoints);
	vector_free(&device->msi_endpoints);
	vector_free(&device->pcie_functions);
	memextent_delete(device->me_cap);
	device->me_cap = CSPACE_CAP_INVALID;
}

static void
device_manager_free_host_bus(host_bus_t *bus)
{
	device_t *device;
	index_t	  j;

	assert(bus != NULL);

	if (bus->pci_host != NULL) {
		free(bus->pci_host);
	}

	if (bus->devices == NULL) {
		goto out;
	}

	foreach_vector_ptr (device_t, bus->devices, j, device) {
		// At this pointer, there *MUST* not be any VM still
		// holding pointers to this device.
		if (device->owner != VMID_PEER_DEFAULT) {
			vm_t *owner = vm_lookup(device->owner);

			if (owner != NULL) {
				assert(owner->buses == NULL);
			}
		}
		device_manager_free_device(device);
	}

	vector_free(&bus->devices);
out:

	return;
}

static void
device_manager_free_virtual_bus(bus_t *bus)
{
	assert(bus != NULL);

	if (bus->device_handles != NULL) {
		vector_free(&bus->device_handles);
	}
}

static error_t
device_manager_init_hlos(vm_t *vm, index_t plat_bus_index)
{
	error_t	    err;
	index_t	    dev_idx;
	device_t   *device;
	host_bus_t *host_bus;
	bus_t	   *virt_bus;

	assert(vm != NULL);

	err = device_manager_add_platform_devices(plat_bus_index);
	if (err != OK) {
		LOG_ERR(err);
		goto out;
	}

	virt_bus = vector_at_ptr(bus_t, vm->buses, plat_bus_index);
	assert(virt_bus != NULL);

	host_bus = vector_at_ptr(host_bus_t, host_buses, plat_bus_index);
	assert(host_bus != NULL);

	// Attach all devices to the HLOS on init. Since there is only a single
	// bus containing all platform devices for now, attach devices from
	// this bus only, to the same virtual bus.
	if (vector_size_ncheck(host_bus->devices) > 0U) {
		foreach_vector_ptr (device_t, host_bus->devices, dev_idx,
				    device) {
			// Do not attach the SMMU when attaching the device to
			// the HLOS for the first time. It is expected that the
			// SIDS are already attached to HLOS by default.
			err = device_manager_virt_bus_add_device(
				virt_bus, device, VMID_HLOS, false);
			if (err != OK) {
				goto err_restore_devices;
			}
		}
	}

	err = OK;
	goto out;

err_restore_devices:
	// TODO: restore devices to initial state. For now, this is not critical
	// as an error here will cause HLOS initialization to fail, which is
	// critical. This will also deinit all of the VM's virtual buses.
out:

	return err;
}

// Note: This function ignores all errors that occur when releasing a device
// from a VM and thus should not be used in contexts where it is critical that
// all device resources are correctly released.
static bool
device_manager_release_next_device(const vm_t *vm)
{
	bool	unreleased_devices = false;
	bus_t  *bus;
	index_t i;

	assert(vm != NULL);
	assert(vm->buses != NULL);

	foreach_vector_ptr (bus_t, vm->buses, i, bus) {
		count_t skip_devices = 0U;
		bool	released     = false;

		if (bus->device_handles == NULL) {
			continue;
		}

		// Note that device_manager_device_release deletes devices from
		// device_handles, changing their indexes and thus making it
		// infeasible to use foreach_vector_ptr here.
		while ((vector_size_ncheck(bus->device_handles) >
			skip_devices) &&
		       !released) {
			device_t	      *device;
			device_lookup_result_t device_r;
			device_handle_t *handle = vector_at(device_handle_t *,
							    bus->device_handles,
							    skip_devices);

			assert(handle != NULL);
			device_r = device_manager_handle_lookup(*handle);
			assert(device_r.device != NULL);
			device = device_r.device;

			// Only release lent devices; donated devices cannot be
			// released and are detached instead.
			if (device->lend_state == DEVICE_LEND_STATE_ACCEPTED) {
				rm_error_t rm_err =
					device_manager_device_release(
						vm->vmid, device, bus, true);

				if (rm_err == RM_OK) {
					released = true;
				} else {
					LOG("device-manager: Release of device "
					    "failed with %d\n",
					    rm_err);
					skip_devices++;
				}
			} else if (device->lend_state ==
				   DEVICE_LEND_STATE_NONE) {
				// The device was donated, detach it.
				error_t err =
					device_manager_virt_bus_remove_device(
						bus, skip_devices, vm->vmid,
						true);
				if (err == OK) {
					released = true;
				} else {
					LOG("device-manager: Remove device failed with %d\n",
					    err);
					skip_devices++;
				}
			} else {
				// Device in offered state, just remove it, no
				// need to detach.
				error_t err =
					device_manager_virt_bus_remove_device(
						bus, skip_devices, vm->vmid,
						false);
				if (err == OK) {
					released = true;
				} else {
					LOG("device-manager: Remove device failed with %d\n",
					    err);
					skip_devices++;
				}
			}
		}

		if (skip_devices >= vector_size_ncheck(bus->device_handles)) {
			// The only devices possibly remaining at this point
			// are donated devices and devices which cannot be
			// released due to some error. Since this function is
			// called when the VM is either being reset or freed,
			// just clean up the memory.
			vector_free(&bus->device_handles);
		} else {
			unreleased_devices = true;
		}

		// If we have released a device, that's enough for now.
		if (released) {
			break;
		}
	}

	// True if we either did not fully iterate over all devices of a bus or
	// if there are still buses left to check.
	return (unreleased_devices || (i < vector_size(vm->buses)));
}

// Interface functions

error_t
device_manager_init(const rm_env_data_t *env_data)
{
	error_t		 err;
	bus_add_result_t bus_r;
	host_bus_t	*bus;
	index_t		 bus_idx;

	assert(env_data != NULL);

	rm_env_data = env_data;

	mmio_ranges = range_list_init(DEVICE_MGR_DEVMEM_START,
				      DEVICE_MGR_DEVMEM_SIZE, true);
	if (mmio_ranges == NULL) {
		err	   = ERROR_NOMEM;
		host_buses = NULL;
		goto out;
	}

	host_buses = vector_init(host_bus_t, 1U, 1U);
	if (host_buses == NULL) {
		err = ERROR_NOMEM;
		goto out;
	}

	// TODO: Get the PCIe Root Complex & allocate pci_host_t
	bus_r = device_manager_add_physical_bus(NULL);
	err   = bus_r.err;
	if (err != OK) {
		LOG_ERR(err);
		goto err_free_host_bus;
	}

	plat_devices_bus_index = bus_r.index;

	goto out;

err_free_host_bus:
	// Clean up the host buses.
	foreach_vector_ptr (host_bus_t, host_buses, bus_idx, bus) {
		device_manager_free_host_bus(bus);
	}
	vector_free(&host_buses);
out:
	if (err != OK) {
		LOG_ERR(err);
	}

	return err;
}

void
device_manager_deinit(void)
{
	vm_t	   *vm = vm_lookup(VMID_HLOS);
	host_bus_t *bus;
	index_t	    i;

	// Deinit HLOS, all other VMs are expected to be deinitialized by
	// whoever created them before this function is called.
	if (vm != NULL) {
		device_manager_deinit_vm(vm);
	}

	if (host_buses == NULL) {
		goto out_free_ranges;
	}

	// Clean up the host buses.
	foreach_vector_ptr (host_bus_t, host_buses, i, bus) {
		device_manager_free_host_bus(bus);
	}
	vector_free(&host_buses);

out_free_ranges:
	if (mmio_ranges == NULL) {
		goto out;
	}
	range_list_deinit(mmio_ranges);
out:

	return;
}

error_t
device_manager_init_vm(vm_t *vm)
{
	error_t		 err;
	bus_add_result_t bus_r;
	host_bus_t	*host_bus;
	bus_t		*bus;
	index_t		 bus_idx;

	assert(vm != NULL);
	assert(vm->buses == NULL);

	LOG("device-manager: Initializing VM %u\n", vm->vmid);
	vm->buses = vector_init(bus_t, vector_size_ncheck(host_buses), 1U);
	if (vm->buses == NULL) {
		err = ERROR_NOMEM;
		goto out;
	}

	// Add a virtual bus for each physical bus so that the association
	// between the physical and virtual buses can be via the bus index.
	// Currently, there is only a single host bus, to which platform
	// devices can be attached to.
	foreach_vector_ptr (host_bus_t, host_buses, bus_idx, host_bus) {
		bus_r = device_manager_add_virtual_bus(vm);
		if (bus_r.err != OK) {
			err = bus_r.err;
			goto out_free;
		}
	}

	if (vm->vmid == VMID_HLOS) {
		assert(plat_devices_bus_index != ~(index_t)0U);
		err = device_manager_init_hlos(vm, plat_devices_bus_index);
		if (err != OK) {
			goto out_free;
		}
	}
	LOG("device-manager: Successfully initialized VM 0x%x\n", vm->vmid);

	err = OK;
	goto out;

out_free:
	foreach_vector_ptr (bus_t, vm->buses, bus_idx, bus) {
		device_manager_free_virtual_bus(bus);
	}
	vector_free(&vm->buses);
out:

	return err;
}

void
device_manager_deinit_vm(vm_t *vm)
{
	bool has_unreleased;

	assert(vm != NULL);

	if (vm->buses == NULL) {
		goto out;
	}

	LOG("device-manager: Deinitializing VM 0x%x\n", vm->vmid);

	// Release devices, in case it was not done during VM reset already.
	// Satisfy MISRA with an explicit block.
	do {
		has_unreleased = device_manager_release_next_device(vm);
	} while (has_unreleased);

	vector_free(&vm->buses);
	LOG("device-manager: Successfully deinitialized VM 0x%x\n", vm->vmid);

out:

	return;
}

bool
device_manager_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			   void *buf, size_t len)
{
	bool handled;

	switch (msg_id) {
	case DEVICE_ACCEPT:
		device_manager_handle_accept(client_id, seq_num, buf, len);
		handled = true;
		break;
	case DEVICE_LEND:
		device_manager_handle_lend(client_id, seq_num, buf, len);
		handled = true;
		break;
	case DEVICE_RELEASE:
		device_manager_handle_release(client_id, seq_num, buf, len);
		handled = true;
		break;
	case DEVICE_RECLAIM:
		device_manager_handle_reclaim(client_id, seq_num, buf, len);
		handled = true;
		break;
	case DEVICE_NOTIFY:
		device_manager_handle_notify(client_id, seq_num, buf, len);
		handled = true;
		break;
	case DEVICE_FIND_HANDLE:
		device_manager_handle_find_handle(client_id, seq_num, buf, len);
		handled = true;
		break;
	case DEVICE_GET_RESOURCES:
		device_manager_handle_get_resources(client_id, seq_num, buf,
						    len);
		handled = true;
		break;
	case DEVICE_BUS_LOCKDOWN:
		device_manager_handle_bus_lockdown(client_id, seq_num, buf,
						   len);
		handled = true;
		break;
	case DEVICE_BUS_UNLOCK:
		device_manager_handle_bus_unlock(client_id, seq_num, buf, len);
		handled = true;
		break;
	case DEVICE_DONATE:
		device_manager_handle_donate(client_id, seq_num, buf, len);
		handled = true;
		break;
	default:
		handled = false;
		break;
	}

	return handled;
}

bool
vm_reset_handle_release_devices(vm_t *vm)
{
	bool unreleased_devices;
	assert(vm != NULL);

	if (vm->buses == NULL) {
		unreleased_devices = false;
		goto out;
	}

	unreleased_devices = device_manager_release_next_device(vm);
	if (!unreleased_devices) {
		vector_free(&vm->buses);
	} else {
		// There are still devices in device_handles, so do not free
		// the buses yet and block the progression to the next VM reset
		// stage.
	}

out:
	return !unreleased_devices;
}

error_t
device_manager_attach_vm(vm_t *vm)
{
	error_t	    err;
	index_t	    bus_idx;
	host_bus_t *host_bus;

	assert(vm != NULL);

	// Accept all devices that were offered to this VM.
	foreach_vector_ptr (host_bus_t, host_buses, bus_idx, host_bus) {
		device_t *device;
		index_t	  dev_idx;

		if (host_bus->devices == NULL) {
			continue;
		}

		foreach_vector_ptr (device_t, host_bus->devices, dev_idx,
				    device) {
			if (device->borrower != vm->vmid) {
				continue;
			}

			if ((device->lend_state ==
			     DEVICE_LEND_STATE_OFFERED_LEND) ||
			    (device->lend_state ==
			     DEVICE_LEND_STATE_OFFERED_DONATE)) {
				bus_t	  *bus;
				rm_error_t rm_err;

				assert(vm->buses != NULL);

				// As long as we do not support bridges or
				// switches, only 1 bus per VM needs to be
				// supported. Thus, simply place devices on the
				// same bus index on the borrowing VM, which
				// should be the root complex.
				// TODO: Once devices other than PCIe devices
				// will be supported, the bus selection needs
				// to take the device type into account.
				bus = vector_at_ptr(bus_t, vm->buses, bus_idx);
				assert(bus != NULL);
				rm_err = device_manager_device_accept(
					vm->vmid, device, bus, true);
				if (rm_err != RM_OK) {
					// TODO: Use error_t for all internal
					// error handling if possible and
					// translate between error_t and
					// rm_error_t at the interface.
					LOG_ERR(rm_err);
					err = ERROR_FAILURE;
					goto out;
				}
			}
		}
	}
	err = OK;

out:

	return err;
}

bool
device_manager_is_device_mmio(paddr_t addr, size_t size)
{
	range_list_find_ret_t range_r;

	assert(mmio_ranges != NULL);

	range_r = range_list_find_range(mmio_ranges, addr, size, PAGE_SIZE);

	return (range_r.err == OK);
}

#endif
