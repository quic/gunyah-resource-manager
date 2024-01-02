// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>
#include <util.h>
#include <utils/dict.h>
#include <utils/vector.h>

#include <event.h>
#include <guest_interface.h>
#include <irq_arch.h>
#include <irq_manager.h>
#include <irq_message.h>
#include <log.h>
#include <panic.h>
#include <random.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm_env_data.h>
#include <virq.h>
#include <vm_mgnt.h>
#include <vm_passthrough_config.h>

#define INVALID_IRQ 0xffffffffU

typedef enum {
	IRQ_TYPE_HW,
	IRQ_TYPE_VIRQ,
} irq_type_t;

typedef enum {
	IRQ_MAP_STATE_RESERVED,
	IRQ_MAP_STATE_UNBOUND,
	IRQ_MAP_STATE_BOUND,
	IRQ_MAP_STATE_LENDING,
} irq_mapping_state_t;

typedef enum {
	IRQ_LEND_STATE_NONE,
	IRQ_LEND_STATE_OFFERED,
	IRQ_LEND_STATE_ACCEPTED,
	IRQ_LEND_STATE_ACCEPTED_STATIC,
} irq_lend_state_t;

RM_PADDED(typedef struct {
	vmid_t	 owner;
	uint32_t owner_irq_number;

	// Hypervisor IDs
	cap_id_t capid;
} hwirq_t)

RM_PADDED(struct irq_manager_vm {
	cap_id_t vic;

	// VM's interrupt ID namespace mappings
	dict_t *irq_mappings_dict;

	uint32_t global_irq_alloc_base; // Base for global irq allocation
})

RM_PADDED(typedef struct {
	irq_type_t type;
	uint32_t   irq_number;

	irq_mapping_state_t state;
} irq_mapping_info_t)

RM_PADDED(typedef struct {
	irq_handle_t	 handle;
	vmid_t		 borrower;
	uint32_t	 borrower_irq_number;
	irq_lend_state_t lend_state;
	label_t		 label;
} irq_lending_t)

// IRQs owned-by tracking
static dict_t *hwirq_owners_dict; // items: hwirq_t *

// Instead of keeping a random handle number and a dict to track them, we for
// now just keep a random handle_base and non-overlapping cpulocal, global and
// virq internal numbering.
static irq_handle_t irq_handle_rand_base;

// IRQ lending state, indexed by HW IRQ number
static dict_t *hwirq_lending_dict;

static bool
irq_number_valid(uint32_t irq_number)
{
	return arch_irq_cpulocal_valid(irq_number) ||
	       arch_irq_global_valid(irq_number);
}

static bool
irq_numbers_compatible(uint32_t irq1, uint32_t irq2)
{
	// Ensure both irq numbers are of the same type
	return (arch_irq_cpulocal_valid(irq1) &&
		arch_irq_cpulocal_valid(irq2)) ||
	       (arch_irq_global_valid(irq1) && arch_irq_global_valid(irq2));
}

static error_t
irq_manager_init_passthrough_irqs(const rm_env_data_t *env_data);

error_t
irq_manager_init(const rm_env_data_t *env_data)
{
	error_t ret;

	assert(hwirq_owners_dict == NULL);
	assert(hwirq_lending_dict == NULL);

	uint64_result_t seed = random_get_entropy64();
	if (seed.e != OK) {
		ret = seed.e;
		goto out;
	}

	assert(env_data != NULL);
	rm_irq_env_data_t *irq_env = env_data->irq_env;
	assert(irq_env != NULL);

	count_t hwirq_max = util_array_size(irq_env->vic_hwirq) - 1U;

	irq_handle_rand_base = (irq_handle_t)seed.r;
	if (util_add_overflows(irq_handle_rand_base, hwirq_max)) {
		irq_handle_rand_base -= hwirq_max;
	}

	static_assert(sizeof(dict_key_t) >= sizeof(irq_handle_rand_base),
		      "handle larger than dict key");

	uint32_t first_irq;
	uint32_t first_cpulocal = 0U, first_global = 0U;

	if (!arch_irq_cpulocal_valid(first_cpulocal)) {
		first_cpulocal = arch_irq_cpulocal_next_valid(first_cpulocal);
		assert(first_cpulocal != 0U);
	}
	if (!arch_irq_global_valid(first_global)) {
		first_global = arch_irq_global_next_valid(first_global);
		assert(first_global != 0U);
	}
	first_irq = util_min(first_cpulocal, first_global);
	assert(hwirq_max > first_irq);

	uint32_t last_irq;
	uint32_t last_cpulocal = arch_irq_cpulocal_max();
	uint32_t last_global   = arch_irq_global_max();

	last_irq = util_max(last_cpulocal, last_global);

	hwirq_owners_dict = dict_init(first_irq, last_irq);
	if (hwirq_owners_dict == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	// Currently irq handles are mapped 1:1 to hwirqs
	hwirq_lending_dict = dict_init(first_irq, last_irq);
	if (hwirq_lending_dict == NULL) {
		ret = ERROR_NOMEM;
		goto out_free;
	}

	ret = OK;
	// Assign all HW global IRQs to HLOS by default
	for (index_t i = first_irq; i <= last_irq; i++) {
		if (irq_env->vic_hwirq[i] == CSPACE_CAP_INVALID) {
			continue;
		}
		ret = irq_manager_hwirq_add(i, irq_env->vic_hwirq[i],
					    VMID_HLOS);
		if (ret != OK) {
			LOG("hwirq %d\n", i);
			goto out_free;
		}
	}

	// Deprecated:
	// Update all restricted IRQs ownership
	uint32_t num_reserved = env_data->num_reserved_dev_irqs;
	assert(num_reserved <= util_array_size(env_data->reserved_dev_irq));

	for (index_t i = 0; i < num_reserved; i++) {
		uint32_t res_irq = env_data->reserved_dev_irq[i];
		if ((res_irq < first_irq) || (res_irq > last_irq) ||
		    (irq_env->vic_hwirq[res_irq] == CSPACE_CAP_INVALID)) {
			LOG("Warning: skipping invalid reserved irq %d\n",
			    res_irq);
			continue;
		}

		ret = irq_manager_hwirq_donate(res_irq, VMID_ANY);
		if (ret != OK) {
			LOG("%i: res irq %d\n", i, res_irq);
			goto out_free;
		}
	}

	// Donate all the passthrough IRQs to the respective VMs
	ret = irq_manager_init_passthrough_irqs(env_data);
	if (ret != OK) {
		goto out;
	}
	vm_t *rm = vm_lookup(VMID_RM);
	assert(rm != NULL);
	ret = irq_manager_vm_init(rm, rm_get_rm_vic(), 511U);

out_free:
	if (ret != OK) {
		dict_deinit(&hwirq_owners_dict);
	}
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

void
irq_manager_deinit(void)
{
	assert(hwirq_owners_dict != NULL);
	assert(hwirq_lending_dict != NULL);

	dict_deinit(&hwirq_owners_dict);
	dict_deinit(&hwirq_lending_dict);
}

error_t
irq_manager_hwirq_add(uint32_t hw_irq_number, cap_id_t capid, vmid_t owner)
{
	assert(hwirq_owners_dict != NULL);

	error_t ret;

	if (!irq_number_valid(hw_irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	hwirq_t *irq = calloc(1, sizeof(*irq));
	if (irq == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	irq->capid	      = capid;
	irq->owner	      = owner;
	irq->owner_irq_number = INVALID_IRQ;

	ret = dict_add(hwirq_owners_dict, hw_irq_number, irq);
	if (ret != OK) {
		// IRQ already in defined, or out of memory
		free(irq);
	}
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

error_t
irq_manager_hwirq_donate(uint32_t hw_irq_number, vmid_t owner)
{
	assert(hwirq_owners_dict != NULL);

	error_t ret;

	if (!irq_number_valid(hw_irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	hwirq_t *irq = dict_get(hwirq_owners_dict, hw_irq_number);

	if (irq == NULL) {
		ret = ERROR_NORESOURCES;
		goto out;
	}
	if (irq->owner == owner) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}
	// Check whether IRQ is currently mapped (or being lent)
	if (irq->owner_irq_number != INVALID_IRQ) {
		ret = ERROR_BUSY;
		goto out;
	}
	irq->owner = owner;

	ret = OK;
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

vmid_result_t
irq_manager_hwirq_get_owner(uint32_t hw_irq_number)
{
	assert(hwirq_owners_dict != NULL);

	vmid_result_t ret = { .e = ERROR_UNIMPLEMENTED };

	hwirq_t *irq = dict_get(hwirq_owners_dict, hw_irq_number);

	if (irq == NULL) {
		ret.e = ERROR_ARGUMENT_INVALID;
	} else {
		ret = vmid_result_ok(irq->owner);
	}

	return ret;
}

error_t
irq_manager_vm_init(vm_t *vm, cap_id_t vic, count_t max_irq)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager == NULL);
	assert(vic != CSPACE_CAP_INVALID);

	irq_manager_vm_t *mgr = calloc(1, sizeof(*vm->irq_manager));
	if (mgr == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	mgr->vic = vic;

	uint32_t first_irq;
	uint32_t first_cpulocal = 0U, first_global = 0U;

	if (!arch_irq_cpulocal_valid(first_cpulocal)) {
		first_cpulocal = arch_irq_cpulocal_next_valid(first_cpulocal);
		assert(first_cpulocal != 0U);
	}
	if (!arch_irq_global_valid(first_global)) {
		first_global = arch_irq_global_next_valid(first_global);
		assert(first_global != 0U);
	}
	first_irq = util_min(first_cpulocal, first_global);
	assert(max_irq > first_irq);

	if (vm->vmid == VMID_RM) {
		mgr->global_irq_alloc_base = first_global;
	} else {
		// TODO: how to set this dynamically ?
		mgr->global_irq_alloc_base = 960U;
	}

	mgr->irq_mappings_dict = dict_init(first_irq, max_irq);

	if (mgr->irq_mappings_dict == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	vm->irq_manager = mgr;

	ret = OK;
out:
	if (ret != OK) {
		if (mgr != NULL) {
			free(mgr);
		}
		LOG_ERR(ret);
	}
	return ret;
}

void
irq_manager_vm_reset(vm_t *vm)
{
	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->vic != CSPACE_CAP_INVALID);

	// Currently we use the vic == CSPACE_CAP_INVALID to tell that the vm
	// is being reset.
	vm->irq_manager->vic = CSPACE_CAP_INVALID;
}

static error_t
irq_manager_vm_hwirq_unmap_internal(const vm_t *vm, uint32_t irq_number,
				    bool free_irq, bool owner);

static error_t
irq_manager_check_deinit_global_irq(const vm_t		     *vm,
				    const irq_mapping_info_t *irq_map,
				    uint32_t		      irq)
{
	error_t ret;

	assert(hwirq_owners_dict != NULL);
	assert(hwirq_lending_dict != NULL);

	assert(irq_map->irq_number != INVALID_IRQ);

	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, irq_map->irq_number);
	assert(hw_irq != NULL);

	if (hw_irq->owner != vm->vmid) {
		// IRQ is borrowed
		ret = ERROR_BUSY;
		goto out;
	}

	irq_lending_t *lend_info =
		dict_get(hwirq_lending_dict, irq_map->irq_number);
	if (lend_info != NULL) {
		// IRQ is lent or not reclaimed
		ret = ERROR_BUSY;
		goto out;
	}

	ret = irq_manager_vm_hwirq_unmap_internal(vm, irq, true, true);
	assert(ret == OK);

	LOG("IRQ_UNMAP: VM %d: IRQ %d\n", vm->vmid, irq);
out:
	return ret;
}

void
irq_manager_vm_deinit(vm_t *vm)
{
	assert(vm != NULL);

	if (vm->irq_manager == NULL) {
		goto out;
	}
	assert(vm->irq_manager->irq_mappings_dict != NULL);

	// Clear all reserved irq mappings and unmap owned HW irqs
	dict_key_t	    key;
	irq_mapping_info_t *irq_map;
	dict_foreach(irq_map, key, vm->irq_manager->irq_mappings_dict)
	{
		if (irq_map == NULL) {
			continue;
		}

		switch (irq_map->type) {
		case IRQ_TYPE_HW:
			if (irq_map->state == IRQ_MAP_STATE_RESERVED) {
				// Reserved IRQ mapping slot
				assert(irq_map->irq_number == INVALID_IRQ);
				error_t err =
					irq_manager_vm_free_global(vm, key);
				assert(err == OK);
			} else if ((irq_map->state == IRQ_MAP_STATE_UNBOUND) ||
				   (irq_map->state == IRQ_MAP_STATE_BOUND)) {
				error_t err =
					irq_manager_check_deinit_global_irq(
						vm, irq_map, key);
				if (err != OK) {
					// Most likely we missed some lending
					// cleanup
					LOG_ERR(err);
					panic("lending cleanup");
				}
				// Note, irq_map was freed in the call above
				irq_map = NULL;
			} else if (irq_map->state == IRQ_MAP_STATE_LENDING) {
				panic("unimplemented");
			} else {
				panic("invalid state");
			}
			break;
		case IRQ_TYPE_VIRQ:
			// We missed an vdevice virq cleanup?
			panic("virq cleanup");
		default:
			panic("unimplemented");
		}
	}

	dict_deinit(&vm->irq_manager->irq_mappings_dict);

	free(vm->irq_manager);
	vm->irq_manager = NULL;

out:
	return;
}

uint32_result_t
irq_manager_vm_alloc_global(const vm_t *vm)
{
	uint32_result_t ret = uint32_result_ok(0U);

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);

	uint32_t irq = vm->irq_manager->global_irq_alloc_base;

	do {
		if (!arch_irq_global_valid(irq)) {
			irq = arch_irq_global_next_valid(irq);
			if (irq == 0U) {
				// No more valid irqs
				ret.e = ERROR_NORESOURCES;
				break;
			}
		}

		dict_key_ret_t key_ret = dict_get_first_free_key_from(
			vm->irq_manager->irq_mappings_dict, irq);
		if (key_ret.err != OK) {
			ret.e = ERROR_NORESOURCES;
			break;
		}
		irq = key_ret.key;
	} while (!arch_irq_global_valid(irq));

	if (ret.e != OK) {
		goto out;
	}

	irq_mapping_info_t *irq_map = calloc(1, sizeof(*irq_map));
	if (irq_map == NULL) {
		ret.e = ERROR_NOMEM;
		goto out;
	}

	irq_map->type	    = IRQ_TYPE_HW;
	irq_map->irq_number = INVALID_IRQ;
	irq_map->state	    = IRQ_MAP_STATE_RESERVED;

	ret.e = dict_add(vm->irq_manager->irq_mappings_dict, irq, irq_map);
	if (ret.e != OK) {
		free(irq_map);
		goto out;
	}

	ret = uint32_result_ok(irq);

out:
	if (ret.e != OK) {
		LOG_ERR(ret.e);
	}
	return ret;
}

error_t
irq_manager_vm_reserve_global(const vm_t *vm, uint32_t irq_number)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);

	if (!arch_irq_global_valid(irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	irq_mapping_info_t *irq_map =
		dict_get(vm->irq_manager->irq_mappings_dict, irq_number);
	if (irq_map != NULL) {
		ret = ERROR_BUSY;
		goto out;
	}

	irq_map = calloc(1, sizeof(*irq_map));
	if (irq_map == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	irq_map->type	    = IRQ_TYPE_HW;
	irq_map->irq_number = INVALID_IRQ;
	irq_map->state	    = IRQ_MAP_STATE_RESERVED;

	ret = dict_add(vm->irq_manager->irq_mappings_dict, irq_number, irq_map);
	if (ret != OK) {
		free(irq_map);
		goto out;
	}

	ret = OK;
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

error_t
irq_manager_vm_free_global(const vm_t *vm, uint32_t irq_number)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);

	if (!arch_irq_global_valid(irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	irq_mapping_info_t *irq_map =
		dict_get(vm->irq_manager->irq_mappings_dict, irq_number);
	if (irq_map == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (irq_map->state != IRQ_MAP_STATE_RESERVED) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	free(irq_map);
	ret = dict_remove(vm->irq_manager->irq_mappings_dict,
			  (dict_key_t)irq_number, NULL);
	assert(ret == OK);

out:
	return ret;
}

error_t
irq_manager_vm_hwirq_map_all_direct(const vm_t *vm)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_owners_dict != NULL);

	dict_key_t key;
	hwirq_t	  *hw_irq;
	dict_foreach(hw_irq, key, hwirq_owners_dict)
	{
		if ((hw_irq == NULL) || (hw_irq->owner != vm->vmid)) {
			continue;
		}

		assert(hw_irq->capid != CSPACE_CAP_INVALID);
		assert(hw_irq->owner_irq_number == INVALID_IRQ);

		irq_mapping_info_t *irq_map = calloc(1, sizeof(*irq_map));
		if (irq_map == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		irq_map->type	    = IRQ_TYPE_HW;
		irq_map->irq_number = key;
		irq_map->state	    = IRQ_MAP_STATE_UNBOUND;

		ret = dict_add(vm->irq_manager->irq_mappings_dict, key,
			       irq_map);
		if (ret != OK) {
			free(irq_map);
			goto out;
		}

		ret = gunyah_hyp_hwirq_bind_virq(hw_irq->capid,
						 vm->irq_manager->vic,
						 irq_map->irq_number);
		if (ret != OK) {
			error_t err = dict_remove(
				vm->irq_manager->irq_mappings_dict, key, NULL);
			assert(err == OK);
			free(irq_map);
			goto out;
		}

		irq_map->state		 = IRQ_MAP_STATE_BOUND;
		hw_irq->owner_irq_number = irq_map->irq_number;
	}

	ret = OK;
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
irq_manager_vm_hwirq_map_internal(const vm_t *vm, uint32_t irq_number,
				  uint32_t hw_irq_number, bool alloc,
				  bool owner)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_owners_dict != NULL);

	if (!irq_numbers_compatible(irq_number, hw_irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, hw_irq_number);
	if (hw_irq == NULL) {
		ret = ERROR_NORESOURCES;
		goto out;
	}
	if (owner && (hw_irq->owner != vm->vmid)) {
		ret = ERROR_DENIED;
		goto out;
	}
	if (owner && (hw_irq->owner_irq_number != INVALID_IRQ)) {
		ret = ERROR_BUSY;
		goto out;
	}
	assert(hw_irq->capid != CSPACE_CAP_INVALID);

	irq_mapping_info_t *irq_map;

	if (!alloc) {
		irq_map = dict_get(vm->irq_manager->irq_mappings_dict,
				   irq_number);
		if (irq_map == NULL) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		if (irq_map->state != IRQ_MAP_STATE_RESERVED) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
		assert(irq_map->irq_number == INVALID_IRQ);
		assert(irq_map->type == IRQ_TYPE_HW);
	} else {
		irq_map = calloc(1, sizeof(*irq_map));
		if (irq_map == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		ret = dict_add(vm->irq_manager->irq_mappings_dict, irq_number,
			       irq_map);
		if (ret != OK) {
			free(irq_map);
			goto out;
		}
	}

	ret = gunyah_hyp_hwirq_bind_virq(hw_irq->capid, vm->irq_manager->vic,
					 irq_number);
	if (ret != OK) {
		if (alloc) {
			error_t err =
				dict_remove(vm->irq_manager->irq_mappings_dict,
					    irq_number, NULL);
			assert(err == OK);
			free(irq_map);
		}
		goto out;
	}

	irq_map->type	    = IRQ_TYPE_HW;
	irq_map->irq_number = hw_irq_number;
	irq_map->state	    = IRQ_MAP_STATE_BOUND;

	if (owner) {
		hw_irq->owner_irq_number = irq_map->irq_number;
	}

	ret = OK;
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

error_t
irq_manager_vm_hwirq_map(const vm_t *vm, uint32_t irq_number,
			 uint32_t hw_irq_number, bool alloc)
{
	return irq_manager_vm_hwirq_map_internal(vm, irq_number, hw_irq_number,
						 alloc, true);
}

static error_t
irq_manager_vm_hwirq_unmap_internal(const vm_t *vm, uint32_t irq_number,
				    bool free_irq, bool owner)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_owners_dict != NULL);

	irq_mapping_info_t *irq_map;

	irq_map = dict_get(vm->irq_manager->irq_mappings_dict, irq_number);
	if (irq_map == NULL) {
		ret = ERROR_NORESOURCES;
		goto out;
	}
	if ((irq_map->state != IRQ_MAP_STATE_BOUND) ||
	    (irq_map->type != IRQ_TYPE_HW)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}
	assert(irq_map->irq_number != INVALID_IRQ);

	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, irq_map->irq_number);
	assert(hw_irq != NULL);
	if (owner) {
		assert(hw_irq->owner == vm->vmid);
		assert(hw_irq->owner_irq_number == irq_number);
	}
	assert(hw_irq->capid != CSPACE_CAP_INVALID);

	ret = gunyah_hyp_hwirq_unbind_virq(hw_irq->capid);
	if ((ret == ERROR_VIRQ_NOT_BOUND) &&
	    (vm->irq_manager->vic == CSPACE_CAP_INVALID)) {
		// It is expected that the VIRQ may have been unbound when the
		// VM's VIC is deleted.
		ret = OK;
	}
	assert(ret == OK);

	if (owner) {
		hw_irq->owner_irq_number = INVALID_IRQ;
	}

	if (free_irq) {
		ret = dict_remove(vm->irq_manager->irq_mappings_dict,
				  (dict_key_t)irq_number, NULL);
		assert(ret == OK);
		free(irq_map);
	} else {
		irq_map->type	    = IRQ_TYPE_HW;
		irq_map->irq_number = INVALID_IRQ;
		irq_map->state	    = IRQ_MAP_STATE_RESERVED;
	}

	ret = OK;
out:
	return ret;
}

error_t
irq_manager_vm_hwirq_unmap(const vm_t *vm, uint32_t irq_number, bool free_irq)
{
	return irq_manager_vm_hwirq_unmap_internal(vm, irq_number, free_irq,
						   true);
}

error_t
irq_manager_vm_virq_map(const vm_t *vm, uint32_t irq_number, bool alloc)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);

	// VIRQs can only be global for now
	if (!arch_irq_global_valid(irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	irq_mapping_info_t *irq_map;

	if (!alloc) {
		irq_map = dict_get(vm->irq_manager->irq_mappings_dict,
				   irq_number);
		if (irq_map == NULL) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		if (irq_map->state != IRQ_MAP_STATE_RESERVED) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
		assert(irq_map->irq_number == INVALID_IRQ);
		assert(irq_map->type == IRQ_TYPE_HW);
	} else {
		irq_map = calloc(1, sizeof(*irq_map));
		if (irq_map == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		ret = dict_add(vm->irq_manager->irq_mappings_dict, irq_number,
			       irq_map);
		if (ret != OK) {
			free(irq_map);
			goto out;
		}
	}

	irq_map->type	    = IRQ_TYPE_VIRQ;
	irq_map->irq_number = irq_number;
	irq_map->state	    = IRQ_MAP_STATE_BOUND;

	ret = OK;
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

error_t
irq_manager_vm_virq_unmap(const vm_t *vm, uint32_t irq_number, bool free_irq)
{
	error_t ret;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);

	// VIRQs can only be global for now
	if (!arch_irq_global_valid(irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	irq_mapping_info_t *irq_map =
		dict_get(vm->irq_manager->irq_mappings_dict, irq_number);
	if (irq_map == NULL) {
		ret = ERROR_NORESOURCES;
		goto out;
	}
	if ((irq_map->state != IRQ_MAP_STATE_BOUND) ||
	    (irq_map->type != IRQ_TYPE_VIRQ)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}
	assert(irq_map->irq_number == irq_number);

	if (free_irq) {
		ret = dict_remove(vm->irq_manager->irq_mappings_dict,
				  (dict_key_t)irq_number, NULL);
		assert(ret == OK);
		free(irq_map);
	} else {
		irq_map->type	    = IRQ_TYPE_HW;
		irq_map->irq_number = INVALID_IRQ;
		irq_map->state	    = IRQ_MAP_STATE_RESERVED;
	}

	ret = OK;
out:
	return ret;
}

static irq_handle_t
irq_manager_handle_alloc(uint32_t hw_irq)
{
	return irq_handle_rand_base + hw_irq;
}

static uint32_t
irq_manager_handle_lookup(irq_handle_t handle)
{
	return handle - irq_handle_rand_base;
}

static void
irq_manager_handle_free(irq_handle_t handle)
{
	(void)handle;
}

static void
irq_manager_handle_lend(vmid_t client_id, uint16_t seq_num, void *buf,
			size_t len)
{
	rm_error_t err;
	error_t	   ret;

	irq_handle_t handle   = (irq_handle_t)-1;
	vmid_t	     borrower = VMID_PEER_DEFAULT;
	uint32_t     src_irq  = (uint32_t)-1;
	label_t	     label    = (label_t)-1;

	assert(buf != NULL);

	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_owners_dict != NULL);
	assert(hwirq_lending_dict != NULL);

	rm_irq_lend_req_t *req = (rm_irq_lend_req_t *)buf;
	if (len != sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}

	borrower = req->borrower;
	src_irq	 = req->virq_num;
	label	 = req->label;

	// === Validations ===

	// - Lookup the IRQ in client
	irq_mapping_info_t *irq_map =
		dict_get(vm->irq_manager->irq_mappings_dict, src_irq);
	if (irq_map == NULL) {
		err = RM_ERROR_IRQ_INVALID;
		goto out_err;
	}
	// -- only support lending bound IRQs for now
	if ((irq_map->type == IRQ_TYPE_HW) &&
	    (irq_map->state == IRQ_MAP_STATE_LENDING)) {
		err = RM_ERROR_IRQ_INUSE;
		goto out_err;
	}
	if ((irq_map->type != IRQ_TYPE_HW) ||
	    (irq_map->state != IRQ_MAP_STATE_BOUND)) {
		err = RM_ERROR_IRQ_INVALID;
		goto out_err;
	}
	uint32_t hw_irq_num = irq_map->irq_number;
	assert(hw_irq_num != INVALID_IRQ);

	// - Check that client is the owner
	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, hw_irq_num);
	if ((hw_irq == NULL) || (hw_irq->owner != client_id)) {
		err = RM_ERROR_IRQ_INVALID;
		goto out_err;
	}
	assert(hw_irq->owner_irq_number == src_irq);
	assert(hw_irq->capid != CSPACE_CAP_INVALID);

	// === Start the Lending ===

	irq_lending_t *lend_info = calloc(1, sizeof(*lend_info));
	if (lend_info == NULL) {
		err = RM_ERROR_NOMEM;
		goto out_err;
	}

	handle = irq_manager_handle_alloc(hw_irq_num);

	ret = dict_add(hwirq_lending_dict, hw_irq_num, lend_info);
	assert(ret != ERROR_DENIED); // Assert not existing entry
	if (ret == ERROR_NOMEM) {
		irq_manager_handle_free(handle);
		free(lend_info);

		err = RM_ERROR_NOMEM;
		goto out_err;
	}
	assert(ret == OK);

	ret = gunyah_hyp_hwirq_unbind_virq(hw_irq->capid);
	assert(ret == OK);

	irq_map->state = IRQ_MAP_STATE_LENDING;

	lend_info->handle	       = handle;
	lend_info->borrower	       = borrower;
	lend_info->borrower_irq_number = INVALID_IRQ;
	lend_info->lend_state	       = IRQ_LEND_STATE_OFFERED;
	lend_info->label	       = label;

	err = RM_OK;

out_err:
	LOG("VM_IRQ_LEND: VM %d to %d: IRQ %d / H %#x L %d, ret %d\n",
	    client_id, borrower, src_irq, handle, label, err);
	if (err == RM_OK) {
		rm_irq_lend_reply_t reply = {
			.handle = handle,
		};
		rm_reply(client_id, VM_IRQ_LEND, seq_num, &reply,
			 sizeof(reply));
	} else {
		rm_standard_reply(client_id, VM_IRQ_LEND, seq_num, err);
	}
}

static rm_error_t
irq_manager_notify_flag_lent(vmid_t client_id, const hwirq_t *hw_irq,
			     const irq_lending_t *lend_info,
			     irq_handle_t handle, void *buf, size_t len)
{
	rm_error_t err;

	count_t		      notify_list_entries = 0U;
	rm_irq_notify_vmid_t *notify_list	  = NULL;

	if (len > sizeof(rm_irq_notify_req_t)) {
		rm_irq_notify_lent_req_t *lent_req =
			(rm_irq_notify_lent_req_t *)buf;
		if (len < sizeof(*lent_req)) {
			err = RM_ERROR_MSG_INVALID;
			goto out;
		}

		notify_list_entries = lent_req->notify_vmid_entries;

		size_t notify_vmids_size =
			notify_list_entries * sizeof(lent_req->notify_vmids[0]);

		if (len != (sizeof(*lent_req) + notify_vmids_size)) {
			err = RM_ERROR_MSG_INVALID;
			goto out;
		}

		notify_list = lent_req->notify_vmids;
	}

	if (hw_irq->owner != client_id) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}
	if (lend_info->lend_state != IRQ_LEND_STATE_OFFERED) {
		err = RM_ERROR_IRQ_INUSE;
		goto out;
	}
	rm_irq_lent_notify_t notify = {
		.owner	     = hw_irq->owner,
		.virq_handle = handle,
		.virq_label  = lend_info->label,
	};
	if (notify_list_entries == 0U) {
		// pass
	} else if (notify_list_entries == 1U) {
		if (notify_list[0].vmid != lend_info->borrower) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
	} else {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	LOG("NOTIFY_VM_IRQ_LENT: VM %d\n", lend_info->borrower);
	rm_notify(lend_info->borrower, NOTIFY_VM_IRQ_LENT, &notify,
		  sizeof(notify));

	err = RM_OK;
out:
	return err;
}

static rm_error_t
irq_manager_notify_flag_released(vmid_t client_id, const hwirq_t *hw_irq,
				 const irq_lending_t *lend_info,
				 irq_handle_t	      handle)
{
	rm_error_t err;

	if (lend_info->borrower != client_id) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}
	if (lend_info->lend_state != IRQ_LEND_STATE_OFFERED) {
		err = RM_ERROR_IRQ_INUSE;
		goto out;
	}

	rm_irq_owner_notify_t notify = {
		.virq_handle = handle,
	};

	LOG("NOTIFY_VM_IRQ_RELEASED: VM %d\n", hw_irq->owner);
	rm_notify(hw_irq->owner, NOTIFY_VM_IRQ_RELEASED, &notify,
		  sizeof(notify));

	err = RM_OK;
out:
	return err;
}

static rm_error_t
irq_manager_notify_flag_accepted(vmid_t client_id, const hwirq_t *hw_irq,
				 const irq_lending_t *lend_info,
				 irq_handle_t	      handle)
{
	rm_error_t err;

	if (lend_info->borrower != client_id) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}
	if (lend_info->lend_state != IRQ_LEND_STATE_ACCEPTED) {
		err = RM_ERROR_IRQ_RELEASED;
		goto out;
	}

	rm_irq_owner_notify_t notify = {
		.virq_handle = handle,
	};

	LOG("NOTIFY_VM_IRQ_ACCEPTED: VM %d\n", hw_irq->owner);
	rm_notify(hw_irq->owner, NOTIFY_VM_IRQ_ACCEPTED, &notify,
		  sizeof(notify));

	err = RM_OK;
out:
	return err;
}

static void
irq_manager_handle_notify(vmid_t client_id, uint16_t seq_num, void *buf,
			  size_t len)
{
	rm_error_t err;

	irq_handle_t handle = (irq_handle_t)-1;

	assert(buf != NULL);

	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_lending_dict != NULL);

	virq_notify_flag_t flags = 0U;

	rm_irq_notify_req_t *req = (rm_irq_notify_req_t *)buf;
	if (len < sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}

	flags = req->flags;
	if ((flags != VIRQ_NOTIFY_FLAG_LENT) && (len != sizeof(*req))) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}

	handle		    = req->handle;
	uint32_t hw_irq_num = irq_manager_handle_lookup(handle);

	// === Validations ===
	irq_lending_t *lend_info = dict_get(hwirq_lending_dict, hw_irq_num);
	if (lend_info == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}
	assert(lend_info->handle == handle);

	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, hw_irq_num);
	assert(hw_irq != NULL);

	switch (flags) {
	case VIRQ_NOTIFY_FLAG_LENT: {
		err = irq_manager_notify_flag_lent(client_id, hw_irq, lend_info,
						   handle, buf, len);
		break;
	}
	case VIRQ_NOTIFY_FLAG_RELEASED: {
		err = irq_manager_notify_flag_released(client_id, hw_irq,
						       lend_info, handle);
		break;
	}
	case VIRQ_NOTIFY_FLAG_ACCEPTED: {
		err = irq_manager_notify_flag_accepted(client_id, hw_irq,
						       lend_info, handle);
		break;
	}
	default:
		err = RM_ERROR_ARGUMENT_INVALID;
		break;
	}

out_err:
	LOG("VM_IRQ_NOTIFY: VM %d: F %#x / H %#x, ret %d\n", client_id, flags,
	    handle, err);
	rm_standard_reply(client_id, VM_IRQ_NOTIFY, seq_num, err);
}

static void
irq_manager_handle_accept(vmid_t client_id, uint16_t seq_num, void *buf,
			  size_t len)
{
	rm_error_t err;

	bool	     alloc   = false;
	irq_handle_t handle  = (irq_handle_t)-1;
	uint32_t     dst_irq = (uint32_t)-1;

	assert(buf != NULL);

	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);
	assert(hwirq_lending_dict != NULL);

	rm_irq_accept_req_t *req = (rm_irq_accept_req_t *)buf;
	if (len != sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}

	handle	= req->handle;
	dst_irq = req->virq_num;
	alloc	= dst_irq == VIRQ_NUM_INVALID;

	uint32_t hw_irq_num = irq_manager_handle_lookup(handle);

	// === Validations ===
	irq_lending_t *lend_info = dict_get(hwirq_lending_dict, hw_irq_num);
	if (lend_info == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}
	if (lend_info->borrower != client_id) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}
	if (lend_info->lend_state != IRQ_LEND_STATE_OFFERED) {
		err = RM_ERROR_IN_USE;
		goto out_err;
	}
	assert(lend_info->handle == handle);

	if (alloc) {
		// FIXME:
		// We allocate 1:1 IRQ number so trusted VMs can validate the
		// IRQs they received. This should ideally only be done for
		// trusted/protected VMs until we have a separate IRQ validate
		// API.
		dst_irq = hw_irq_num;
	}
	error_t ret = irq_manager_vm_hwirq_map_internal(vm, dst_irq, dst_irq,
							true, false);
	if (ret != OK) {
		if (ret == ERROR_NOMEM) {
			err = RM_ERROR_NOMEM;
		} else if (ret == ERROR_DENIED) {
			err = RM_ERROR_DENIED;
		} else {
			err = RM_ERROR_ARGUMENT_INVALID;
		}
		goto out_err;
	}

	lend_info->lend_state	       = IRQ_LEND_STATE_ACCEPTED;
	lend_info->borrower_irq_number = dst_irq;

	err = RM_OK;

out_err:
	LOG("VM_IRQ_ACCEPT: VM %d: IRQ %d / A %d H %#x, ret %d\n", client_id,
	    dst_irq, (uint32_t)alloc, handle, err);
	if (err == RM_OK) {
		rm_irq_accept_reply_t reply = {
			.virq_num = dst_irq,
		};
		rm_reply(client_id, VM_IRQ_ACCEPT, seq_num, &reply,
			 sizeof(reply));
	} else {
		rm_standard_reply(client_id, VM_IRQ_ACCEPT, seq_num, err);
	}
}

static void
irq_manager_handle_release(vmid_t client_id, uint16_t seq_num, void *buf,
			   size_t len)
{
	rm_error_t err;

	irq_handle_t handle  = (irq_handle_t)-1;
	uint32_t     irq_num = INVALID_IRQ;

	assert(buf != NULL);

	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);
	assert(hwirq_lending_dict != NULL);

	rm_irq_release_req_t *req = (rm_irq_release_req_t *)buf;
	if (len != sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}

	handle = req->handle;

	uint32_t hw_irq_num = irq_manager_handle_lookup(handle);

	// === Validations ===
	irq_lending_t *lend_info = dict_get(hwirq_lending_dict, hw_irq_num);
	if (lend_info == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}
	if (lend_info->borrower != client_id) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}
	if (lend_info->lend_state != IRQ_LEND_STATE_ACCEPTED) {
		err = RM_ERROR_IN_USE;
		goto out_err;
	}
	assert(lend_info->handle == handle);
	assert(lend_info->borrower_irq_number != INVALID_IRQ);
	irq_num = lend_info->borrower_irq_number;

	error_t ret =
		irq_manager_vm_hwirq_unmap_internal(vm, irq_num, true, false);
	if (ret != OK) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out_err;
	}

	lend_info->lend_state	       = IRQ_LEND_STATE_OFFERED;
	lend_info->borrower_irq_number = INVALID_IRQ;

	err = RM_OK;

out_err:
	LOG("VM_IRQ_RELEASE: VM %d: IRQ %d / H %#x, ret %d\n", client_id,
	    irq_num, handle, err);
	rm_standard_reply(client_id, VM_IRQ_RELEASE, seq_num, err);
}

static void
irq_manager_handle_reclaim(vmid_t client_id, uint16_t seq_num, void *buf,
			   size_t len)
{
	rm_error_t err;

	irq_handle_t handle   = (irq_handle_t)-1;
	vmid_t	     borrower = VMID_PEER_DEFAULT;
	uint32_t     src_irq  = (uint32_t)-1;

	assert(buf != NULL);

	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_owners_dict != NULL);
	assert(hwirq_lending_dict != NULL);

	rm_irq_reclaim_req_t *req = (rm_irq_reclaim_req_t *)buf;
	if (len != sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		goto out_err;
	}
	handle = req->handle;

	uint32_t hw_irq_num = irq_manager_handle_lookup(handle);

	// === Validations ===
	irq_lending_t *lend_info = dict_get(hwirq_lending_dict, hw_irq_num);
	if (lend_info == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}
	if (lend_info->borrower == client_id) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out_err;
	}
	if (lend_info->lend_state != IRQ_LEND_STATE_OFFERED) {
		err = RM_ERROR_IN_USE;
		goto out_err;
	}
	assert(lend_info->handle == handle);
	assert(lend_info->borrower_irq_number == INVALID_IRQ);

	// - Check that client is the owner
	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, hw_irq_num);
	if ((hw_irq == NULL) || (hw_irq->owner != client_id)) {
		err = RM_ERROR_IRQ_INVALID;
		goto out_err;
	}
	assert(hw_irq->capid != CSPACE_CAP_INVALID);
	assert(hw_irq->owner_irq_number != INVALID_IRQ);

	src_irq = hw_irq->owner_irq_number;

	// - Lookup the IRQ in client
	irq_mapping_info_t *irq_map =
		dict_get(vm->irq_manager->irq_mappings_dict, src_irq);
	if (irq_map == NULL) {
		err = RM_ERROR_IRQ_INVALID;
		goto out_err;
	}
	if ((irq_map->type != IRQ_TYPE_HW) &&
	    (irq_map->state != IRQ_MAP_STATE_LENDING)) {
		err = RM_ERROR_IRQ_INVALID;
		goto out_err;
	}

	error_t ret;

	borrower = lend_info->borrower;

	// === Perform the Reclaim ===
	ret = gunyah_hyp_hwirq_bind_virq(hw_irq->capid, vm->irq_manager->vic,
					 irq_map->irq_number);
	assert(ret == OK);

	irq_map->state = IRQ_MAP_STATE_BOUND;

	ret = dict_remove(hwirq_lending_dict, (dict_key_t)hw_irq_num, NULL);
	assert(ret == OK);
	free(lend_info);

	irq_manager_handle_free(handle);

	err = RM_OK;

out_err:
	LOG("VM_IRQ_RECLAIM: VM %d from %d: IRQ %d / H %#x, ret %d\n",
	    client_id, borrower, src_irq, handle, err);
	rm_standard_reply(client_id, VM_IRQ_RECLAIM, seq_num, err);
}

static error_t
irq_manager_check_release_global_irq(const vm_t *vm, uint32_t hw_irq_number,
				     uint32_t irq)
{
	error_t ret;

	irq_handle_t handle = (irq_handle_t)-1;

	assert(hwirq_owners_dict != NULL);
	assert(hwirq_lending_dict != NULL);
	assert(hw_irq_number != INVALID_IRQ);

	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, hw_irq_number);
	assert(hw_irq != NULL);

	if (hw_irq->owner == vm->vmid) {
		// Owner is not borrowing, nothing to do
		ret = OK;
		goto out;
	}

	irq_lending_t *lend_info = dict_get(hwirq_lending_dict, hw_irq_number);
	assert(lend_info != NULL);
	assert(lend_info->borrower == vm->vmid);
	assert(lend_info->borrower_irq_number == irq);

	irq_lend_state_t lend_state = lend_info->lend_state;
	// If STATE_RELEASED, the irq_map should have already been freed
	assert((lend_state == IRQ_LEND_STATE_ACCEPTED) ||
	       (lend_state == IRQ_LEND_STATE_ACCEPTED_STATIC));

	ret = irq_manager_vm_hwirq_unmap_internal(vm, irq, true, false);
	assert(ret == OK);

	// Release the IRQ and reset borrower as the VM is reset
	lend_info->lend_state	       = IRQ_LEND_STATE_OFFERED;
	lend_info->borrower	       = VMID_PEER_DEFAULT;
	lend_info->borrower_irq_number = INVALID_IRQ;
	handle			       = lend_info->handle;

	// deprecated: restricted/static_lend reclaim
	if (lend_state == IRQ_LEND_STATE_ACCEPTED_STATIC) {
		ret = dict_remove(hwirq_lending_dict, (dict_key_t)hw_irq_number,
				  NULL);
		assert(ret == OK);
		free(lend_info);
		lend_info = NULL;

		irq_manager_handle_free(handle);

		if (hw_irq->owner == VMID_ANY) {
			LOG("restricted reclaim: %d: VM %d IRQ %d\n",
			    hw_irq_number, hw_irq->owner, irq);
		} else {
			LOG("static_lend reclaim: %d: VM %d IRQ %d\n",
			    hw_irq_number, hw_irq->owner, irq);

			assert(hw_irq->owner == VMID_HLOS);
			vm_t *owner = vm_lookup(hw_irq->owner);
			assert(owner != NULL);
			assert(owner->irq_manager != NULL);
			assert(owner->irq_manager->irq_mappings_dict != NULL);

			irq_mapping_info_t *irq_map =
				dict_get(owner->irq_manager->irq_mappings_dict,
					 hw_irq->owner_irq_number);
			assert(irq_map != NULL);
			assert(irq_map->state == IRQ_MAP_STATE_LENDING);
			assert(irq_map->type == IRQ_TYPE_HW);
			assert(irq_map->irq_number == hw_irq_number);

			ret = gunyah_hyp_hwirq_bind_virq(
				hw_irq->capid, owner->irq_manager->vic,
				irq_map->irq_number);
			assert(ret == OK);
			irq_map->state = IRQ_MAP_STATE_BOUND;
		}
	}

	LOG("IRQ_RELEASED: VM %d: IRQ %d / H %#x\n", vm->vmid, irq, handle);
out:
	return ret;
}

// Deprecated
error_t
irq_manager_vm_restricted_lend(const vm_t *vm, uint32_t irq_number,
			       uint32_t hw_irq_number)
{
	error_t ret;

	irq_handle_t handle = (irq_handle_t)-1;
	vmid_t	     borrower;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_owners_dict != NULL);
	assert(hwirq_lending_dict != NULL);

	borrower = vm->vmid;

	// === Validations ===
	if (!irq_numbers_compatible(irq_number, hw_irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out_err;
	}

	// - Lookup the IRQ in VM
	irq_mapping_info_t *irq_map =
		dict_get(vm->irq_manager->irq_mappings_dict, irq_number);
	if (irq_map != NULL) {
		ret = ERROR_BUSY;
		goto out_err;
	}

	// - Check that VMID_ANY is the owner
	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, hw_irq_number);
	if ((hw_irq == NULL) || (hw_irq->owner != VMID_ANY)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out_err;
	}
	assert(hw_irq->owner_irq_number == INVALID_IRQ);
	assert(hw_irq->capid != CSPACE_CAP_INVALID);

	irq_lending_t *lend_info = dict_get(hwirq_lending_dict, hw_irq_number);
	if (lend_info != NULL) {
		// IRQ is lent or not reclaimed
		ret = ERROR_BUSY;
		goto out_err;
	}

	// === Start the Lending ===

	lend_info = calloc(1, sizeof(*lend_info));
	if (lend_info == NULL) {
		ret = ERROR_NOMEM;
		goto out_err;
	}

	handle = irq_manager_handle_alloc(hw_irq_number);

	ret = dict_add(hwirq_lending_dict, hw_irq_number, lend_info);
	assert(ret != ERROR_DENIED); // Assert not existing entry
	if (ret == ERROR_NOMEM) {
		goto out_free;
	}
	assert(ret == OK);

	ret = irq_manager_vm_hwirq_map_internal(vm, irq_number, hw_irq_number,
						true, false);
	if (ret == ERROR_NOMEM) {
		error_t err =
			dict_remove(hwirq_lending_dict, hw_irq_number, NULL);
		assert(err == OK);
		goto out_free;
	}
	assert(ret == OK);

	lend_info->handle	       = handle;
	lend_info->borrower	       = borrower;
	lend_info->borrower_irq_number = irq_number;
	lend_info->lend_state	       = IRQ_LEND_STATE_ACCEPTED_STATIC;
	lend_info->label	       = (label_t)-1;

	ret = OK;

out_free:
	if (ret != OK) {
		irq_manager_handle_free(handle);
		free(lend_info);
	}
out_err:
	LOG("vm_restricted_lend: %d -> VM %d: IRQ %d, ret %d\n", hw_irq_number,
	    borrower, irq_number, ret);
	return ret;
}

// Deprecated
error_t
irq_manager_vm_static_lend(const vm_t *vm, uint32_t irq_number,
			   uint32_t hw_irq_number)
{
	error_t ret;

	irq_handle_t handle = (irq_handle_t)-1;
	vmid_t	     borrower;

	assert(vm != NULL);
	assert(vm->irq_manager != NULL);
	assert(vm->irq_manager->irq_mappings_dict != NULL);
	assert(hwirq_owners_dict != NULL);
	assert(hwirq_lending_dict != NULL);

	borrower = vm->vmid;

	// === Validations ===

	if (!irq_numbers_compatible(irq_number, hw_irq_number)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out_err;
	}

	// - Lookup the IRQ in VM
	irq_mapping_info_t *irq_map =
		dict_get(vm->irq_manager->irq_mappings_dict, irq_number);
	if (irq_map != NULL) {
		ret = ERROR_BUSY;
		goto out_err;
	}

	// - Check that VMID_HLOS is the owner
	hwirq_t *hw_irq = dict_get(hwirq_owners_dict, hw_irq_number);
	if ((hw_irq == NULL) || (hw_irq->owner != VMID_HLOS)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out_err;
	}
	assert(hw_irq->owner_irq_number != INVALID_IRQ);
	assert(hw_irq->capid != CSPACE_CAP_INVALID);

	irq_lending_t *lend_info = dict_get(hwirq_lending_dict, hw_irq_number);
	if (lend_info != NULL) {
		// IRQ is lent or not reclaimed
		ret = ERROR_BUSY;
		goto out_err;
	}

	// === Start the Lending ===

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);
	assert(hlos->irq_manager != NULL);
	assert(hlos->irq_manager->irq_mappings_dict != NULL);

	irq_map = dict_get(hlos->irq_manager->irq_mappings_dict,
			   hw_irq->owner_irq_number);
	assert(irq_map != NULL);
	assert(irq_map->state == IRQ_MAP_STATE_BOUND);
	assert(irq_map->type == IRQ_TYPE_HW);
	assert(irq_map->irq_number == hw_irq_number);

	// - Unmap from HLOS
	ret = gunyah_hyp_hwirq_unbind_virq(hw_irq->capid);
	assert(ret == OK);

	lend_info = calloc(1, sizeof(*lend_info));
	if (lend_info == NULL) {
		ret = ERROR_NOMEM;
		goto out_err;
	}

	handle = irq_manager_handle_alloc(hw_irq_number);

	ret = dict_add(hwirq_lending_dict, hw_irq_number, lend_info);
	assert(ret != ERROR_DENIED); // Assert not existing entry
	if (ret == ERROR_NOMEM) {
		goto out_free;
	}
	assert(ret == OK);

	ret = irq_manager_vm_hwirq_map_internal(vm, irq_number, hw_irq_number,
						true, false);
	if (ret == ERROR_NOMEM) {
		error_t err =
			dict_remove(hwirq_lending_dict, hw_irq_number, NULL);
		assert(err == OK);
		goto out_free;
	}
	assert(ret == OK);

	irq_map->state = IRQ_MAP_STATE_LENDING;

	lend_info->handle	       = handle;
	lend_info->borrower	       = borrower;
	lend_info->borrower_irq_number = irq_number;
	lend_info->lend_state	       = IRQ_LEND_STATE_ACCEPTED_STATIC;
	lend_info->label	       = (label_t)-1;

	ret = OK;

out_free:
	if (ret != OK) {
		irq_manager_handle_free(handle);
		free(lend_info);
	}
out_err:
	LOG("vm_static_lend: HLOS %d -> VM %d: IRQ %d, ret %d\n", hw_irq_number,
	    borrower, irq_number, ret);
	return ret;
}

bool
vm_reset_handle_release_irqs(vmid_t vmid)
{
	bool ret;

	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	if (vm->irq_manager == NULL) {
		ret = true;
		goto out;
	}

	assert(vm->irq_manager->irq_mappings_dict != NULL);

	dict_key_t	    key;
	irq_mapping_info_t *irq_map;

	dict_foreach(irq_map, key, vm->irq_manager->irq_mappings_dict)
	{
		if (irq_map == NULL) {
			continue;
		}

		switch (irq_map->type) {
		case IRQ_TYPE_HW:
			if (irq_map->state == IRQ_MAP_STATE_RESERVED) {
				// Reserved IRQ mapping slot
				assert(irq_map->irq_number == INVALID_IRQ);
			} else if ((irq_map->state == IRQ_MAP_STATE_UNBOUND) ||
				   (irq_map->state == IRQ_MAP_STATE_BOUND)) {
				// Check if borrowing
				error_t err =
					irq_manager_check_release_global_irq(
						vm, irq_map->irq_number, key);
				assert(err == OK);
				// Note, irq_map may have been freed
				irq_map = NULL;
			} else if (irq_map->state == IRQ_MAP_STATE_LENDING) {
				panic("unimplemented");
			} else {
				panic("invalid state");
			}
			break;
		case IRQ_TYPE_VIRQ:
			// Currently no VIRQ lending support
			assert(irq_map->state == IRQ_MAP_STATE_BOUND);
			break;
		default:
			panic("unimplemented");
		}
	}

	ret = true;
out:
	return ret;
}

bool
irq_manager_lending_msg_handler(vmid_t client_id, uint32_t msg_id,
				uint16_t seq_num, void *buf, size_t len)
{
	(void)client_id;
	(void)seq_num;
	(void)buf;
	(void)len;

	bool handled;

	switch (msg_id) {
	case VM_IRQ_ACCEPT:
		irq_manager_handle_accept(client_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_IRQ_LEND:
		irq_manager_handle_lend(client_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_IRQ_RELEASE:
		irq_manager_handle_release(client_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_IRQ_RECLAIM:
		irq_manager_handle_reclaim(client_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_IRQ_NOTIFY:
		irq_manager_handle_notify(client_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_IRQ_UNMAP:
		LOG_LOC("VM_IRQ_UNMAP");
		handled = false;
		break;
	default:
		handled = false;
		break;
	}

	return handled;
}

// This API changes the passthrough device assignments and assign the irqs
// configured for each device with the configured VMID. This API change the IRQ
// ownership of irqs configured for passthrough devices from HLOS to the VMID
// configured for the passthrough device. Returns error either in case the IRQ
// is not owned by HLOS or the irq donate fails.
static error_t
irq_manager_init_passthrough_irqs(const rm_env_data_t *env_data)
{
	error_t ret = OK;
	for (index_t i = 0; i < env_data->device_assignments->num_devices;
	     i++) {
		uint32_t vmid = env_data->device_assignments->devices[i].vmid;
		for (index_t j = 0;
		     j < env_data->device_assignments->devices[i].num_irqs;
		     j++) {
			uint32_t pt_irq =
				env_data->device_assignments->devices[i].irqs[j];

			hwirq_t *irq = dict_get(hwirq_owners_dict, pt_irq);
			if (irq == NULL) {
				ret = ERROR_NORESOURCES;
				LOG("Invalid passthrough irq:%u of vmid:%u",
				    pt_irq, vmid);
			} else if (irq->owner != VMID_HLOS) {
				ret = ERROR_BUSY;
				LOG("The passthrough irq:%u of vmid:%u is not owned by HLOS ",
				    pt_irq, vmid);
			} else {
				ret = irq_manager_hwirq_donate(pt_irq,
							       (vmid_t)vmid);
				if (ret != OK) {
					LOG("Failed to map passthrough irq:%u of vmid:%u",
					    pt_irq, vmid);
				}
			}
			if (ret != OK) {
				goto out;
			}
		}
	}
out:
	return ret;
}
