// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <irq_message.h>
#include <memparcel_msg.h>
#include <platform_vm_config.h>
#include <rm-rpc-fifo.h>
#include <util.h>
#include <utils/dict.h>
#include <utils/list.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

// The first VIRQ number that can be used to attach HW IRQs. This is
// platform-specific and should be defined elsewhere.
static const virq_t VIRQ_FIRST_VALID   = (virq_t)16U;
static const virq_t VIRQ_RM_VIRT_START = (virq_t)32U;
static const virq_t VIRQ_VIRT_START    = (virq_t)960U;

static void
handle_accept(vmid_t client_id, uint16_t seq_num, virq_handle_t handle,
	      virq_t virq_num);

static void
handle_lend(vmid_t client_id, uint16_t seq_num, vmid_t borrower,
	    virq_t virq_num, label_t label);

static void
handle_release(vmid_t client_id, uint16_t seq_num, virq_handle_t handle);

static void
handle_reclaim(vmid_t client_id, uint16_t seq_num, virq_handle_t handle);

static void
handle_notify(vmid_t client_id, uint16_t seq_num, virq_handle_t handle,
	      virq_notify_flag_t flags, size_t vmids_cnt,
	      rm_irq_notify_vmid_t *vmids);

static void
handle_unmap(vmid_t client_id, uint16_t seq_num, size_t virq_num_cnt,
	     virq_t virq_nums[]);

RM_PADDED(typedef struct {
	bool	 is_reserved; // virq number is reserved
	bool	 is_valid;
	bool	 is_owner;
	bool	 is_lent;
	bool	 is_mapped;
	virq_t	 virq;
	uint32_t hw_irq;
	cap_id_t hw_irq_cap;
} irq_mapping_info_t)

RM_PADDED(struct vm_irq_manager {
	cap_id_t vic;

	// dict key is virq number, and irq_mapping_info is the value
	dict_t *mapping_dict;

	struct irq_mapping *irq_mapping_prev;
	struct irq_mapping *irq_mapping_next;
})

RM_PADDED(typedef struct {
	virq_handle_t	    virq_handle;
	bool		    is_borrowed;
	vmid_t		    owner;
	irq_mapping_info_t *owner_info;
	vmid_t		    holder;
	virq_t		    holder_virq;
	label_t		    label;
} virq_handle_info_t)

RM_PADDED(typedef struct virq_handle_manager {
	// key is virq_handle, value is virq_handle_info
	dict_t *handle_dict;
} virq_handle_manager_t)

// ownership of HW, its array (global, only one) can be used to map between
// hardware irq (index) and it's current holder.
typedef struct {
	vmid_t vm;
} irq_owner_t;

static virq_handle_manager_t handle_manager;
static bool		     debug = false;

static vm_irq_manager_t *rm_irq_manager = NULL;

typedef struct {
	virq_t	   virq_num;
	rm_error_t err;
} irq_manager_borrow_irq_ret_t;

// Borrow hwirq based on the lender's request. It will create mapping for
// virq: hwirq, and mark this mapping as borrowed.
// It will also check if the handle is already borrowed.
static irq_manager_borrow_irq_ret_t
irq_manager_borrow_irq(virq_handle_info_t *info, vmid_t borrower,
		       virq_t virq_num);

// borrower would unbind the virq:hwirq and will not use the hwirq any more.
static rm_error_t
irq_manager_release_irq(virq_handle_info_t *info);

// Reclaim irq based on handle. It will bind the original mapping.
static rm_error_t
irq_manager_reclaim_irq(virq_handle_info_t *info);

// Lend the virq:hwirq to others. This function should mark this mapping is
// lent, and also release the virq: hwirq binding.
// But it's OK to keep the record since it will reclaim it. We might free
// the memory for memory footprint size consideration.
static void
irq_manager_lend_irq(irq_mapping_info_t *info);

// Directly unmap virq: hwirq pairs, just ignore if such virq
// doesn't have mapping. And this map means drop the ownership. So the record
// will be deleted.
static rm_error_t
irq_manager_unmap_irqs(vmid_t owner, size_t virq_num_cnt, virq_t virq_nums[]);

typedef struct {
	virq_t	   virq_num;
	rm_error_t err;
} create_irq_mapping_ret_t;

// Record/map for virq:hwirq, low level op.
// Assume owner is valid.
// It will do the checking, create record of virq:hwirq mapping pair for owner,
// and directly map virq to hwirq.
static create_irq_mapping_ret_t
create_irq_mapping(vm_irq_manager_t *manager, virq_t virq_num, cap_id_t hwirq,
		   bool does_own);

RM_PADDED(typedef struct {
	irq_mapping_info_t *info;
	vm_irq_manager_t	 *manager;
	rm_error_t	    err;
} irq_manager_get_ret_t)

// Check if the specified virq belongs to the owner, and mapped to an existing
// hw irq, and the current virq: hwirq still hold by the owner (has't been
// lent)
static irq_manager_get_ret_t
irq_manager_get(vmid_t owner, virq_t virq_num);

RM_PADDED(typedef struct {
	virq_handle_t handle;
	rm_error_t    err;
} virq_handle_manager_alloc_ret_t)

// Create a irq handler for specific virq: hwirq mapping. It also records the
// target borrower, so borrower can borrow it in the future.
static virq_handle_manager_alloc_ret_t
virq_handle_manager_alloc(irq_mapping_info_t *info, vmid_t owner,
			  vmid_t borrower, label_t label);

RM_PADDED(typedef struct {
	virq_handle_info_t *info;
	rm_error_t	    err;
} virq_handle_manager_get_ret_t)

// Get the handle specified handle info
static virq_handle_manager_get_ret_t
virq_handle_manager_get(virq_handle_t handle);

static void
virq_handle_manager_free(virq_handle_t handle, virq_handle_info_t *info);

// Find all the mappings for a specific VM
static vm_irq_manager_t *
irq_manager_lookup(vmid_t owner);

static rm_error_t
map_irq(irq_mapping_info_t *info, cap_id_t vic);

static rm_error_t
unmap_irq(irq_mapping_info_t *info);

static void
dump(vm_irq_manager_t *manager);

static virq_t
irq_manager_allocate_virq(vm_irq_manager_t *manager)
{
	assert(manager != NULL);

	dict_t *dict = manager->mapping_dict;
	assert(dict != NULL);

	// FIXME: add manager->virq_base instead of VIRQ_FIRST_VALID
	return (virq_t)dict_get_first_free_key_from(dict, VIRQ_FIRST_VALID);
}

vm_irq_manager_t *
irq_manager_create(cap_id_t vic, count_t num_hwirqs, const cap_id_t *hwirqs)
{
	assert((hwirqs != NULL) || (num_hwirqs == 0));

	vm_irq_manager_t *manager =
		(vm_irq_manager_t *)calloc(1, sizeof(*manager));
	if (manager == NULL) {
		goto out;
	}

	manager->vic = vic;

	// init dict
	// FIXME: should specify a correct capacity
	manager->mapping_dict = dict_init();
	if (manager->mapping_dict == NULL) {
		free(manager);
		manager = NULL;
		goto out;
	}

	for (index_t i = 0; i < num_hwirqs; i++) {
		cap_id_t hwirq = hwirqs[i];

		if (hwirq == CSPACE_CAP_INVALID) {
			continue;
		}

		create_irq_mapping_ret_t ret =
			create_irq_mapping(manager, i, hwirq, true);
		// should not be wrong
		if (ret.err != RM_OK) {
			dict_deinit(manager->mapping_dict);
			free(manager);
			manager = NULL;
			goto out;
		}
	}

	if (debug) {
		dump(manager);
	}
out:
	return manager;
}

rm_error_t
irq_manager_init(void)
{
	rm_error_t ret = RM_OK;

	// init global handle control struct
	handle_manager.handle_dict = dict_init();

	rm_irq_manager = irq_manager_create(rm_get_rm_vic(), 0, NULL);
	if (rm_irq_manager == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

out:
	return ret;
}

rm_error_t
map_irq(irq_mapping_info_t *info, cap_id_t vic)
{
	rm_error_t ret;

	assert(info != NULL);
	assert(info->is_valid);
	assert(!info->is_lent);
	assert(!info->is_mapped);
	assert(info->hw_irq_cap != CSPACE_CAP_INVALID);

	error_t err =
		gunyah_hyp_hwirq_bind_virq(info->hw_irq_cap, vic, info->virq);
	if (err == ERROR_ARGUMENT_INVALID) {
		// Requested VIRQ number is out of range
		ret = RM_ERROR_ARGUMENT_INVALID;
	} else if (err == ERROR_BUSY) {
		// Requested VIRQ number is already in use
		ret = RM_ERROR_IRQ_NOT_MAPPED;
	} else if (err == OK) {
		info->is_mapped = true;
		ret		= RM_OK;
	} else {
		ret = RM_ERROR_DENIED;
	}

	return ret;
}

rm_error_t
unmap_irq(irq_mapping_info_t *info)
{
	rm_error_t ret;

	assert(info != NULL);
	assert(info->is_valid);
	assert(info->is_mapped);

	error_t err = gunyah_hyp_hwirq_unbind_virq(info->hw_irq_cap);
	if (err == OK) {
		info->is_mapped = false;
		ret		= RM_OK;
	} else {
		ret = RM_ERROR_DENIED;
	}

	return ret;
}

irq_manager_borrow_irq_ret_t
irq_manager_borrow_irq(virq_handle_info_t *info, vmid_t borrower,
		       virq_t virq_num)
{
	irq_manager_borrow_irq_ret_t ret;

	// check if it's expected holder
	if (borrower != info->holder) {
		ret.err	     = RM_ERROR_VALIDATE_FAILED;
		ret.virq_num = VIRQ_INVALID;
		goto out;
	}

	vm_irq_manager_t *manager = irq_manager_lookup(borrower);
	if (manager == NULL) {
		ret.err	     = RM_ERROR_VMID_INVALID;
		ret.virq_num = VIRQ_INVALID;
		goto out;
	}

	if (!info->is_borrowed) {
		assert(info->owner_info != NULL);
		assert(info->owner_info->is_owner);

		if (virq_num == VIRQ_INVALID) {
			// Allocate 1:1
			virq_num = info->owner_info->hw_irq;
			assert(virq_num != VIRQ_INVALID);
		}
		create_irq_mapping_ret_t create_ret = create_irq_mapping(
			manager, virq_num, info->owner_info->hw_irq_cap, false);

		ret.err	     = create_ret.err;
		ret.virq_num = create_ret.virq_num;

		if (create_ret.err == RM_OK) {
			// update handle info
			info->is_borrowed = true;
			info->holder_virq = create_ret.virq_num;
		}
	} else {
		ret.err	     = RM_ERROR_IRQ_INUSE;
		ret.virq_num = info->holder_virq;
	}

out:
	return ret;
}

rm_error_t
irq_manager_static_share(vmid_t source_vmid, virq_t source_virq,
			 vmid_t dest_vmid, virq_t dest_virq)
{
	rm_error_t err;

	irq_manager_get_ret_t get_ret =
		irq_manager_get(source_vmid, source_virq);
	if (get_ret.err != RM_OK) {
		// lookup failed
		err = get_ret.err;
		goto out;
	}
	irq_mapping_info_t *irq_info = get_ret.info;

	if (!irq_info->is_valid || !irq_info->is_owner) {
		err = RM_ERROR_IRQ_INVALID;
		goto out;
	}
	if (irq_info->is_lent) {
		err = RM_ERROR_IRQ_INUSE;
		goto out;
	}
	assert(irq_info->is_mapped);

	vm_irq_manager_t *manager = irq_manager_lookup(dest_vmid);
	if (manager == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (dest_virq == VIRQ_INVALID) {
		dest_virq = irq_manager_allocate_virq(manager);
		if (dest_virq > VIRQ_LAST_VALID) {
			err = RM_ERROR_NORESOURCE;
			goto out;
		}
	}

	irq_manager_lend_irq(irq_info);

	create_irq_mapping_ret_t create_ret = create_irq_mapping(
		manager, dest_virq, irq_info->hw_irq_cap, false);
	err = create_ret.err;

	if (err != OK) {
		// Restore the source VM's mapping
		irq_info->is_lent = false;
		(void)map_irq(irq_info, source_virq);
		goto out;
	}
out:
	return err;
}

rm_error_t
irq_manager_reserve_virq(vmid_t vmid, virq_t virq, bool is_virt)
{
	rm_error_t err = RM_OK;

	vm_irq_manager_t *manager = irq_manager_lookup(vmid);
	if (manager == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	dict_t *dict = manager->mapping_dict;
	assert(dict != NULL);

	irq_mapping_info_t *irq_info =
		(irq_mapping_info_t *)dict_get(dict, virq);
	if (irq_info != NULL) {
		if (!irq_info->is_valid || irq_info->is_reserved || is_virt ||
		    (irq_info->hw_irq != VIRQ_INVALID)) {
			err = RM_ERROR_IRQ_INUSE;
			goto out;
		}
		// valid hw_irq
		irq_info->is_reserved = true;
	} else {
		irq_info = calloc(1, sizeof(*irq_info));
		if (irq_info == NULL) {
			err = RM_ERROR_NOMEM;
			goto out;
		}

		irq_info->is_reserved = true;

		if (is_virt) {
			irq_info->is_valid = true;
		}

		irq_info->virq	     = virq;
		irq_info->hw_irq     = VIRQ_INVALID;
		irq_info->hw_irq_cap = CSPACE_CAP_INVALID;

		dict_add(dict, (dict_key_t)virq, (void *)irq_info);
	}

out:
	return err;
}

irq_manager_get_free_virt_virq_ret_t
irq_manager_get_free_virt_virq(vmid_t vmid)
{
	irq_manager_get_free_virt_virq_ret_t ret = { .err = RM_OK };

	vm_irq_manager_t *manager = irq_manager_lookup(vmid);
	if (manager == NULL) {
		ret.err = RM_ERROR_VMID_INVALID;
		goto err_vmid_invalid;
	}

	dict_t *dict = manager->mapping_dict;
	assert(dict != NULL);

	dict_key_t start_from = 0U;
	if (vmid == VMID_RM) {
		start_from = VIRQ_RM_VIRT_START;
	} else {
		start_from = VIRQ_VIRT_START;
	}

	virq_t free_virq =
		(virq_t)dict_get_first_free_key_from(dict, start_from);

	// virt virq (for vdevice) is restricted from
	// [VIRQ_VIRT_START, VIRQ_LAST_VALID), if this range is exhausted
	// we will need to find a better solution
	assert(free_virq <= VIRQ_LAST_VALID);

	ret.virq = free_virq;

err_vmid_invalid:
	return ret;
}

error_t
irq_manager_return_virq(vmid_t vmid, virq_t virq)
{
	error_t ret = OK;

	vm_irq_manager_t *manager = irq_manager_lookup(vmid);
	if (manager == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto err_manager;
	}

	dict_t *dict = manager->mapping_dict;
	assert(dict != NULL);

	irq_mapping_info_t *irq_info =
		(irq_mapping_info_t *)dict_get(dict, virq);
	if (irq_info == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto err_virq_get;
	}

	if (!irq_info->is_valid || !irq_info->is_reserved) {
		ret = ERROR_DENIED;
		goto err_wrong_status;
	}

	if (irq_info->hw_irq == VIRQ_INVALID) {
		irq_info->is_reserved = false;
	} else {
		free(irq_info);
		dict_remove(dict, (dict_key_t)virq);
	}

err_wrong_status:
err_virq_get:
err_manager:
	return ret;
}

rm_error_t
irq_manager_release_irq(virq_handle_info_t *info)
{
	rm_error_t err = RM_OK;

	// check if handle is borrowed
	if (!info->is_borrowed) {
		// either it's released or not borrowed, no need to
		// distinguish the difference.
		err = RM_ERROR_IRQ_RELEASED;
		goto out;
	}
	assert(info->owner_info != NULL);

	// get the holder's mapping info
	irq_manager_get_ret_t ret =
		irq_manager_get(info->holder, info->holder_virq);
	if (ret.err == RM_ERROR_IRQ_NOT_MAPPED) {
		// irq already unmapped?
		err = RM_OK;
		goto release;
	} else if (ret.err != RM_OK) {
		err = ret.err;
		goto out;
	}
	irq_mapping_info_t *irq_info = ret.info;

	if (!irq_info->is_valid || (irq_info->virq != info->holder_virq)) {
		// virq was possibly unmapped and new irq mapped
		err = RM_OK;
		goto release;
	}

	// sanity checks
	assert(!irq_info->is_owner);
	assert(irq_info->is_mapped);
	assert(irq_info->hw_irq_cap == info->owner_info->hw_irq_cap);

	rm_error_t unmap_ret = unmap_irq(irq_info);
	// FIXME: assume unmap always works in this case
	assert(unmap_ret == RM_OK);

	// remove it from dict if not also a reservation
	irq_info->is_valid = false;
	if (!irq_info->is_reserved) {
		dict_t *dict = ret.manager->mapping_dict;
		assert(dict != NULL);

		dict_remove(dict, irq_info->virq);
		free(irq_info);
	}

release:
	// update handler to mark the release
	info->is_borrowed = false;
	info->holder_virq = VIRQ_INVALID;

out:
	return err;
}

rm_error_t
irq_manager_reclaim_irq(virq_handle_info_t *info)
{
	rm_error_t err = RM_OK;

	assert(info != NULL);

	// check if the handle is released by holder
	if (info->is_borrowed) {
		err = RM_ERROR_IRQ_INUSE;
		goto out;
	}
	assert(info->holder_virq == VIRQ_INVALID);

	// get the owner's mapping info
	irq_manager_get_ret_t get_ret =
		irq_manager_get(info->owner, info->owner_info->virq);
	if (get_ret.err != RM_OK) {
		err = get_ret.err;
		goto out;
	}

	// Sanity checks
	assert(info->owner_info == get_ret.info);
	assert(info->owner_info->is_valid);
	assert(info->owner_info->is_owner);
	assert(info->owner_info->is_lent);
	assert(!info->owner_info->is_mapped);

	info->owner_info->is_lent = false;

	// map it back to owner
	err = map_irq(info->owner_info, get_ret.manager->vic);

	info->is_borrowed = false;
	info->owner_info  = NULL;

	// it's time to release handle
	virq_handle_manager_free(info->virq_handle, info);
	info = NULL;
out:
	return err;
}

void
irq_manager_lend_irq(irq_mapping_info_t *irq_info)
{
	assert(irq_info != NULL);
	assert(irq_info->is_valid);
	assert(irq_info->is_owner);
	assert(!irq_info->is_lent);

	if (irq_info->is_mapped) {
		rm_error_t err = unmap_irq(irq_info);
		// shouldn't have issue, or else, internal status wrong
		assert(err == RM_OK);
	}

	irq_info->is_lent = true;
}

rm_error_t
irq_manager_unmap_irqs(vmid_t owner, size_t virq_num_cnt, virq_t virq_nums[])
{
	rm_error_t err = RM_OK;

	// find the virq info
	vm_irq_manager_t *mappings = irq_manager_lookup(owner);
	if (mappings == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	dict_t *dict = mappings->mapping_dict;
	assert(dict != NULL);

	// Check virqs first
	for (index_t i = 0; i < virq_num_cnt; ++i) {
		irq_mapping_info_t *irq_info =
			(irq_mapping_info_t *)dict_get(dict, virq_nums[i]);
		if ((irq_info == NULL) || !irq_info->is_valid) {
			err = RM_ERROR_IRQ_INVALID;
			goto out;
		}
		if (irq_info->is_owner && irq_info->is_lent) {
			err = RM_ERROR_IRQ_INUSE;
			goto out;
		}
		if (!irq_info->is_mapped) {
			err = RM_ERROR_IRQ_NOT_MAPPED;
			goto out;
		}
	}

	for (index_t i = 0; i < virq_num_cnt; ++i) {
		irq_mapping_info_t *irq_info =
			(irq_mapping_info_t *)dict_get(dict, virq_nums[i]);
		assert(irq_info != NULL);

		err = unmap_irq(irq_info);
		// shouldn't have issue, or else, internal status wrong
		assert(err == RM_OK);

		// FIXME: unmap of owner virqs will lose them permanently

		// remove it from dict if not also a reservation
		irq_info->is_valid = false;
		if (!irq_info->is_reserved) {
			dict_remove(dict, (dict_key_t)irq_info->virq);
			free(irq_info);
		}
	}
out:
	return err;
}

create_irq_mapping_ret_t
create_irq_mapping(vm_irq_manager_t *manager, virq_t virq_num, cap_id_t hwirq,
		   bool does_own)
{
	create_irq_mapping_ret_t ret;

	assert(manager != NULL);

	dict_t *dict = manager->mapping_dict;
	assert(dict != NULL);

	assert(virq_num != VIRQ_INVALID);

	if ((virq_num < VIRQ_FIRST_VALID) || (virq_num > VIRQ_LAST_VALID)) {
		ret.err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// check if there's already a mapping for virq
	irq_mapping_info_t *irq_info =
		(irq_mapping_info_t *)dict_get(dict, virq_num);
	if (irq_info != NULL) {
		if (irq_info->is_valid) {
			ret.err = RM_ERROR_IRQ_INUSE;
			goto out;
		}
		assert(irq_info->is_reserved);
		assert(irq_info->virq == virq_num);
	} else {
		// allocate a new irq_mapping_info
		irq_info = calloc(1, sizeof(*irq_info));
		if (irq_info == NULL) {
			ret.err = RM_ERROR_NOMEM;
			goto out;
		}
		irq_info->virq = virq_num;
		// do this for free irq_info later, fixes SA false-positive
		irq_info->is_reserved = false;
	}

	irq_info->is_valid = true;
	// need to wait until mapping to hwirq
	irq_info->is_mapped  = false;
	irq_info->is_lent    = false;
	irq_info->is_owner   = does_own;
	irq_info->hw_irq_cap = hwirq;

	if (does_own) {
		// FIXME, assumes hw_irq num == virq_num when does_own is true
		irq_info->hw_irq = virq_num;
	} else {
		irq_info->hw_irq = VIRQ_INVALID;
	}

	// map irq
	ret.err = map_irq(irq_info, manager->vic);

	if (!irq_info->is_reserved) {
		if (ret.err == RM_OK) {
			dict_add(dict, (dict_key_t)virq_num, (void *)irq_info);
		} else {
			free(irq_info);
			goto out;
		}
	}

out:
	if (ret.err == RM_OK) {
		ret.virq_num = virq_num;
	} else {
		ret.virq_num = VIRQ_INVALID;
	}

	return ret;
}

vm_irq_manager_t *
irq_manager_lookup(vmid_t vmid)
{
	vm_irq_manager_t *ret = NULL;

	if (vmid == VMID_RM) {
		ret = rm_irq_manager;
		goto out;
	}

	vm_t *vm = vm_lookup(vmid);
	if (vm != NULL) {
		ret = vm->vm_config->irq_manager;
	}

out:
	return ret;
}

irq_manager_get_ret_t
irq_manager_get(vmid_t vmid, virq_t virq_num)
{
	irq_manager_get_ret_t ret = {
		.err	 = RM_OK,
		.info	 = NULL,
		.manager = NULL,
	};

	ret.manager = irq_manager_lookup(vmid);
	if (ret.manager == NULL) {
		ret.err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	dict_t *dict = ret.manager->mapping_dict;
	assert(dict != NULL);

	ret.info = (irq_mapping_info_t *)dict_get(dict, virq_num);
	if (ret.info == NULL) {
		ret.err	    = RM_ERROR_IRQ_NOT_MAPPED;
		ret.manager = NULL;
		goto out;
	}

out:
	return ret;
}

virq_handle_manager_alloc_ret_t
virq_handle_manager_alloc(irq_mapping_info_t *irq_info, vmid_t owner,
			  vmid_t borrower, label_t label)
{
	assert(irq_info != NULL);

	virq_handle_t key = (virq_handle_t)dict_get_first_free_key(
		handle_manager.handle_dict);

	virq_handle_manager_alloc_ret_t ret = {
		.err = RM_OK,
	};

	virq_handle_info_t *handle_info = calloc(1, sizeof(*handle_info));
	if (handle_info == NULL) {
		ret.err = RM_ERROR_NOMEM;
		goto out;
	}

	// fill the data into handle
	handle_info->is_borrowed = false;
	// need to be set during accept
	handle_info->holder_virq = VIRQ_INVALID;
	handle_info->owner	 = owner;
	handle_info->owner_info	 = irq_info;
	handle_info->holder	 = borrower;
	handle_info->label	 = label;
	handle_info->virq_handle = key;

	dict_add(handle_manager.handle_dict, (dict_key_t)key,
		 (void *)handle_info);
	ret.handle = key;
out:
	return ret;
}

virq_handle_manager_get_ret_t
virq_handle_manager_get(virq_handle_t handle)
{
	virq_handle_manager_get_ret_t ret;

	dict_t *dict = handle_manager.handle_dict;
	assert(dict != NULL);

	ret.info = dict_get(dict, (dict_key_t)handle);
	if (ret.info != NULL) {
		ret.err = RM_OK;
	} else {
		ret.err = RM_ERROR_HANDLE_INVALID;
	}

	return ret;
}

void
virq_handle_manager_free(virq_handle_t handle, virq_handle_info_t *info)
{
	dict_t *dict = handle_manager.handle_dict;
	assert(dict_contains(dict, (dict_key_t)handle));

	dict_remove(dict, (dict_key_t)handle);

	free(info);
}

bool
irq_manager_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len)
{
	bool ret = true;

	switch (msg_id) {
	case VM_IRQ_ACCEPT: {
		rm_irq_accept_req_t *req = (rm_irq_accept_req_t *)buf;

		if (len != sizeof(*req)) {
			printf("Error: invalid msg, len(%zu) != %zu\n", len,
			       sizeof(*req));
			ret = false;
			break;
		}

		handle_accept(client_id, seq_num, req->handle, req->virq_num);
		break;
	}

	case VM_IRQ_LEND: {
		rm_irq_lend_req_t *req = (rm_irq_lend_req_t *)buf;

		if (len != sizeof(*req)) {
			printf("Error: invalid msg, len(%zu) != %zu\n", len,
			       sizeof(*req));
			ret = false;
			break;
		}

		handle_lend(client_id, seq_num, req->borrower, req->virq_num,
			    req->label);
		break;
	}

	case VM_IRQ_RELEASE: {
		rm_irq_release_req_t *req = (rm_irq_release_req_t *)buf;

		if (len != sizeof(*req)) {
			printf("Error: invalid msg, len(%zu) != %zu\n", len,
			       sizeof(*req));
			ret = false;
			break;
		}

		handle_release(client_id, seq_num, req->handle);
		break;
	}

	case VM_IRQ_RECLAIM: {
		rm_irq_reclaim_req_t *req = (rm_irq_reclaim_req_t *)buf;

		if (len != sizeof(*req)) {
			printf("Error: invalid msg, len(%zu) != %zu\n", len,
			       sizeof(*req));
			ret = false;
			break;
		}

		handle_reclaim(client_id, seq_num, req->handle);
		break;
	}

	case VM_IRQ_NOTIFY: {
		rm_irq_notify_req_t *req = (rm_irq_notify_req_t *)buf;

		if (len < sizeof(*req)) {
			printf("Error: invalid msg, len(%zu) < %zu\n", len,
			       sizeof(*req));
			ret = false;
			break;
		}

		if ((req->flags & 1U) != 0U) {
			rm_irq_notify_lent_req_t *lent_req =
				(rm_irq_notify_lent_req_t *)buf;
			if (len < sizeof(*lent_req)) {
				printf("Error: invalid msg, len(%zu) < %zu\n",
				       len, sizeof(*lent_req));
				ret = false;
				break;
			}

			size_t notify_vmids_size =
				lent_req->notify_vmid_entries *
				sizeof(lent_req->notify_vmids[0]);

			if (len != (sizeof(*lent_req) + notify_vmids_size)) {
				printf("Error: invalid msg, len(%zu) != %zu\n",
				       len,
				       sizeof(*lent_req) + notify_vmids_size);
				ret = false;
				break;
			}

			handle_notify(client_id, seq_num, lent_req->handle,
				      lent_req->flags,
				      lent_req->notify_vmid_entries,
				      lent_req->notify_vmids);
		} else {
			if (len != sizeof(*req)) {
				printf("Error: invalid msg, len(%zu) != %zu\n",
				       len, sizeof(*req));
				ret = false;
				break;
			}

			handle_notify(client_id, seq_num, req->handle,
				      req->flags, 0, NULL);
		}

		break;
	}

	case VM_IRQ_UNMAP: {
		rm_irq_unmap_req_t *req = (rm_irq_unmap_req_t *)buf;

		if (len < sizeof(*req)) {
			printf("Error: invalid msg, len(%zu) != %zu\n", len,
			       sizeof(*req));
			ret = false;
			break;
		}
		if (util_mult_integer_overflows(req->virq_entry_cnt,
						sizeof(req->virq_nums[0]))) {
			printf("Error: invalid msg, virq_entry_cnt = %zu, virq_nums = %u\n",
			       req->virq_entry_cnt, req->virq_nums[0]);
			ret = false;
			break;
		}
		size_t unmap_virqs_size =
			req->virq_entry_cnt * sizeof(req->virq_nums[0]);

		if (util_add_overflows(sizeof(*req), unmap_virqs_size)) {
			printf("Error: invalid msg, len overflows. req size = %zu, unmap_virqs_size = %zu\n",
			       sizeof(*req), unmap_virqs_size);
		}

		if (len != (sizeof(*req) + unmap_virqs_size)) {
			printf("Error: invalid msg, len(%zu) != %zu\n", len,
			       sizeof(*req) + unmap_virqs_size);
			ret = false;
			break;
		}

		handle_unmap(client_id, seq_num, req->virq_entry_cnt,
			     req->virq_nums);
		break;
	}

	default:
		ret = false;
		break;
	}

	if (debug) {
		dump(irq_manager_lookup(client_id));
	}

	return ret;
}

void
handle_accept(vmid_t client_id, uint16_t seq_num, virq_handle_t handle,
	      virq_t virq_num)
{
	printf("handle_accept: handle(0x%x) virq_num(%d)\n", handle, virq_num);

	// check if handle is valid
	virq_handle_manager_get_ret_t get_ret = virq_handle_manager_get(handle);
	if (get_ret.err != RM_OK) {
		rm_standard_reply(client_id, VM_IRQ_ACCEPT, seq_num,
				  get_ret.err);
		goto out;
	}

	irq_manager_borrow_irq_ret_t borrow_ret =
		irq_manager_borrow_irq(get_ret.info, client_id, virq_num);

	if ((borrow_ret.err == RM_OK) ||
	    (borrow_ret.err == RM_ERROR_IRQ_INUSE)) {
		rm_irq_accept_rep_t rep = { .virq_num = borrow_ret.virq_num };

		rm_reply_error(client_id, VM_IRQ_ACCEPT, seq_num,
			       borrow_ret.err, &rep, sizeof(rep));
	} else {
		rm_standard_reply(client_id, VM_IRQ_ACCEPT, seq_num,
				  borrow_ret.err);
	}

out:
	return;
}

void
handle_lend(vmid_t client_id, uint16_t seq_num, vmid_t borrower,
	    virq_t virq_num, label_t label)
{
	printf("handle_lend: borrower(0x%x) virq_num(%d) label(0x%x)\n",
	       borrower, virq_num, label);

	// check if virq_num owns by owner
	irq_manager_get_ret_t get_ret = irq_manager_get(client_id, virq_num);
	if (get_ret.err != RM_OK) {
		// lookup failed
		rm_standard_reply(client_id, VM_IRQ_LEND, seq_num, get_ret.err);
		goto out;
	}
	irq_mapping_info_t *irq_info = get_ret.info;
	assert(irq_info != NULL);

	if (!irq_info->is_owner) {
		// client is not owner of this virq
		rm_standard_reply(client_id, VM_IRQ_LEND, seq_num,
				  RM_ERROR_IRQ_INVALID);
		goto out;
	}
	if (irq_info->is_lent) {
		rm_standard_reply(client_id, VM_IRQ_LEND, seq_num,
				  RM_ERROR_IRQ_INUSE);
		goto out;
	}

	virq_handle_manager_alloc_ret_t alloc_ret = virq_handle_manager_alloc(
		get_ret.info, client_id, borrower, label);
	if (alloc_ret.err != RM_OK) {
		rm_standard_reply(client_id, VM_IRQ_LEND, seq_num,
				  alloc_ret.err);
		goto out;
	}

	// everything is OK, now unmap virq from it's owner
	irq_manager_lend_irq(get_ret.info);

	rm_irq_lend_rep_t rep = {
		.handle = alloc_ret.handle,
	};
	size_t rep_sz = sizeof(rep);

	rm_reply(client_id, VM_IRQ_LEND, seq_num, &rep, rep_sz);
out:
	return;
}

void
handle_release(vmid_t client_id, uint16_t seq_num, virq_handle_t handle)
{
	printf("handle_release: handle(0x%x)\n", handle);

	// check if handle is valid
	virq_handle_manager_get_ret_t get_ret = virq_handle_manager_get(handle);
	if (get_ret.err != RM_OK) {
		rm_standard_reply(client_id, VM_IRQ_RELEASE, seq_num,
				  get_ret.err);
		goto out;
	}

	if (get_ret.info->holder != client_id) {
		// ask for something doesn't belong to it
		rm_standard_reply(client_id, VM_IRQ_RELEASE, seq_num,
				  RM_ERROR_HANDLE_INVALID);
		goto out;
	}

	rm_error_t err = irq_manager_release_irq(get_ret.info);

	rm_standard_reply(client_id, VM_IRQ_RELEASE, seq_num, err);
out:
	return;
}

void
handle_reclaim(vmid_t client_id, uint16_t seq_num, virq_handle_t handle)
{
	printf("handle_reclaim: handle(0x%x)\n", handle);

	// check if handle is valid
	virq_handle_manager_get_ret_t get_ret = virq_handle_manager_get(handle);
	if (get_ret.err != RM_OK) {
		rm_standard_reply(client_id, VM_IRQ_RELEASE, seq_num,
				  get_ret.err);
		goto out;
	}

	if (get_ret.info->owner != client_id) {
		// ask for something dosn't belong to it
		rm_standard_reply(client_id, VM_IRQ_RECLAIM, seq_num,
				  RM_ERROR_HANDLE_INVALID);
		goto out;
	}

	rm_error_t err = irq_manager_reclaim_irq(get_ret.info);
	get_ret.info   = NULL;

	rm_standard_reply(client_id, VM_IRQ_RECLAIM, seq_num, err);
out:
	return;
}

void
handle_notify(vmid_t client_id, uint16_t seq_num, virq_handle_t handle,
	      virq_notify_flag_t flags, size_t vmids_cnt,
	      rm_irq_notify_vmid_t *vmids)
{
	printf("handle_notify: handle(0x%x) flags(0x%x), vmids_cnt(%lu), vmids[",
	       handle, flags, vmids_cnt);
	for (index_t i = 0; i < vmids_cnt; ++i) {
		printf("%d, ", (int)vmids[i].vmid);
	}
	printf("]\n");

	rm_error_t notify_err = RM_OK;

	// check if handle is valid
	virq_handle_manager_get_ret_t get_ret = virq_handle_manager_get(handle);
	if (get_ret.err != RM_OK) {
		notify_err = get_ret.err;
		goto out;
	}

	if (flags == VIRQ_NOTIFY_FLAG_LENT) {
		if (get_ret.info->owner != client_id) {
			// ask for something dosn't belong to it
			notify_err = RM_ERROR_HANDLE_INVALID;
			goto out;
		}

		// tell borrower there's an irq lent
		for (index_t i = 0; i < vmids_cnt; i++) {
			rm_irq_lent_notify_t notify = {
				.owner	     = get_ret.info->owner,
				.virq_handle = handle,
				.virq_label  = get_ret.info->label,
			};

			rm_notify(vmids[i].vmid, NOTIFY_VM_IRQ_LENT, &notify,
				  sizeof(notify));
		}
	} else if (flags == VIRQ_NOTIFY_FLAG_RELEASED) {
		if (get_ret.info->holder != client_id) {
			// ask for something dosn't belong to it
			notify_err = RM_ERROR_HANDLE_INVALID;
			goto out;
		}

		if (get_ret.info->is_borrowed) {
			// Can't notify release when the IRQ is still borrowed
			notify_err = RM_ERROR_IRQ_INUSE;
			goto out;
		}

		rm_irq_owner_notify_t notify = {
			.virq_handle = handle,
		};

		// told lender there's a irq released
		rm_notify(get_ret.info->owner, NOTIFY_VM_IRQ_RELEASED, &notify,
			  sizeof(notify));
	} else if (flags == VIRQ_NOTIFY_FLAG_ACCEPTED) {
		if (get_ret.info->holder != client_id) {
			// IRQ not lent to this VM
			notify_err = RM_ERROR_HANDLE_INVALID;
			goto out;
		}

		if (!get_ret.info->is_borrowed) {
			// IRQ not currently accepted
			notify_err = RM_ERROR_IRQ_RELEASED;
			goto out;
		}

		rm_irq_owner_notify_t notify = {
			.virq_handle = handle,
		};

		rm_notify(get_ret.info->owner, NOTIFY_VM_IRQ_ACCEPTED, &notify,
			  sizeof(notify));
	} else {
		notify_err = RM_ERROR_ARGUMENT_INVALID;
	}

out:
	rm_standard_reply(client_id, VM_IRQ_NOTIFY, seq_num, notify_err);
}

void
handle_unmap(vmid_t client_id, uint16_t seq_num, size_t virq_num_cnt,
	     virq_t virq_nums[])
{
	printf("handle_unmap: virq_num_cnt(%lu), virq_nums[", virq_num_cnt);
	for (index_t i = 0; i < virq_num_cnt; ++i) {
		printf("%d, ", virq_nums[i]);
	}
	printf("]\n");

	rm_error_t err =
		irq_manager_unmap_irqs(client_id, virq_num_cnt, virq_nums);

	rm_standard_reply(client_id, VM_IRQ_UNMAP, seq_num, err);
}

void
dump(vm_irq_manager_t *manager)
{
	if (manager != NULL) {
		printf("=== irq mappings ===\n");
		dict_t	       *dict     = manager->mapping_dict;
		irq_mapping_info_t *map_info = NULL;
		int		    fmt_cnt  = 0;
		const int	    item_cnt = 14;

		printf("owned: {\n");
		printf("key: virq_num->hwirq:\n");
		fmt_cnt = 0;
		for (dict_key_t virq = 0; virq < dict->capacity; ++virq) {
			map_info = (irq_mapping_info_t *)dict_get(dict, virq);
			if ((map_info != NULL) && (map_info->is_mapped) &&
			    (map_info->is_owner)) {
				printf("%3ld: %3d->%3ld", virq, map_info->virq,
				       map_info->hw_irq_cap);
				++fmt_cnt;

				if (fmt_cnt % item_cnt == 0) {
					printf("\n");
				} else {
					printf("\t");
				}
			}
		}
		if (fmt_cnt % item_cnt != 0) {
			printf("\n");
		}
		printf("}\n\n");

		printf("lent: {\n");
		printf("key: virq_num->hwirq:\n");
		fmt_cnt = 0;
		for (dict_key_t virq = 0; virq < dict->capacity; ++virq) {
			map_info = (irq_mapping_info_t *)dict_get(dict, virq);
			if ((map_info != NULL) && (!map_info->is_mapped) &&
			    (map_info->is_owner)) {
				printf("%3ld: %3d->%#lx\n", virq,
				       map_info->virq, map_info->hw_irq_cap);
				++fmt_cnt;

				if (fmt_cnt % item_cnt == 0) {
					printf("\n");
				} else {
					printf("\t");
				}
			}
		}
		if (fmt_cnt % item_cnt != 0) {
			printf("\n");
		}
		printf("\n}\n\n");

		printf("borrowed: {\n");
		printf("key: virq_num->hwirq:\n");
		fmt_cnt = 0;
		for (dict_key_t virq = 0; virq < dict->capacity; ++virq) {
			map_info = (irq_mapping_info_t *)dict_get(dict, virq);
			if ((map_info != NULL) && (map_info->is_mapped) &&
			    (!map_info->is_owner)) {
				printf("%3ld: %3d->%#lx\n", virq,
				       map_info->virq, map_info->hw_irq_cap);
				++fmt_cnt;

				if (fmt_cnt % item_cnt == 0) {
					printf("\n");
				} else {
					printf("\t");
				}
			}
		}
		if (fmt_cnt % item_cnt != 0) {
			printf("\n");
		}
		printf("}\n\n");
	}

	printf("=== irq handles ===\n");

	dict_t	       *dict	= handle_manager.handle_dict;
	virq_handle_info_t *handle_info = NULL;
	for (dict_key_t handle = 0; handle < dict->capacity; ++handle) {
		handle_info = (virq_handle_info_t *)dict_get(dict, handle);
		if (handle_info != NULL) {
			printf("\thandle(0x%8lx): is_borrowed(%s) "
			       "holder_virq(%3d) owner_virq(%3d) hwirq(%#lx) "
			       "owner(0x%3x) holder(0x%3x)\n",
			       handle, handle_info->is_borrowed ? "Y" : "N",
			       handle_info->holder_virq,
			       handle_info->owner_info->virq,
			       handle_info->owner_info->hw_irq_cap,
			       handle_info->owner, handle_info->holder);
		}
	}
	printf("\n\n");
}
