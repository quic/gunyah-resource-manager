// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <compiler.h>
#include <guest_interface.h>
#include <log.h>
#include <memparcel.h>
#include <platform.h>
#include <rm-rpc-fifo.h>
#include <util.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_creation.h>
#include <vm_mgnt.h>
#include <vm_mgnt_message.h>

// Bitmap of secondary VM VMIDs.
static uint64_t secondary_vmids;

// Bitmap of peripheral VMIDs, which are not controlled by RM.
static uint64_t peripheral_vmids;

// Bitmap of free vmids - set bit means VMID is free.
// Only 64 VMIDs for now!
static uint64_t free_vmids;

static vector_t *all_vms;

RM_PADDED(typedef struct peer_info {
	uint16_t     id_len;
	char	     *id_buf;
	vm_id_type_t id_type;
} peer_info_t)

static error_t
parse_guid(const char *guid_string, uint8_t guid[VM_GUID_LEN]);
static error_t
vm_mgnt_parse_peer_id(char *peer_id, peer_info_t *info);

rm_error_t
vm_mgnt_send_state(vm_t *vm)
{
	vmid_t owner = vm->owner;
	assert(owner != VMID_RM);

	rm_notify_vm_status_t msg = { 0 };

	msg.vm_vmid    = vm->vmid;
	msg.vm_status  = (uint8_t)vm->vm_state;
	msg.os_status  = (uint8_t)vm->os_state;
	msg.app_status = (uint16_t)vm->app_status;

	// Send VM state notification to all peer VMs
	size_t cnt = vector_size(vm->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **peer_vm = vector_at_ptr(vm_t *, vm->peers, i);
		if ((*peer_vm) == NULL) {
			continue;
		}
		LOG("NOTIFY_VM_STATUS: to: %d [%d: %d/%d/%d]\n",
		    (*peer_vm)->vmid, vm->vmid, vm->vm_state, vm->os_state,
		    vm->app_status);
		rm_notify((*peer_vm)->vmid, NOTIFY_VM_STATUS, &msg,
			  sizeof(msg));
	}

	return RM_OK;
}

rm_error_t
vm_mgnt_new_vm(vmid_t vmid, vmid_t owner)
{
	rm_error_t ret = RM_OK;
	vm_t	     *vm;

	vm = calloc(1, sizeof(vm_t));

	if (vm == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	vm->vmid     = vmid;
	vm->owner    = owner;
	vm->vm_state = VM_STATE_INIT;

	error_t vec_err = vector_push_back(all_vms, vm);
	if (vec_err != OK) {
		free(vm);
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	vm->peers = vector_init(vm_t *, 1U, 1U);

	if (owner != VMID_RM) {
		// Add owner VM as peer
		vm_t *owner_vm = vm_lookup(owner);
		assert(owner_vm != NULL);

		error_t reg_err = vm_register_peers(vm, owner_vm);
		if (reg_err != OK) {
			(void)vector_pop_back(vm_t *, all_vms);
			free(vm);
			ret = RM_ERROR_NOMEM;
			goto out;
		}
	}
out:
	return ret;
}

void
vm_mgnt_set_name(vm_t *vm, const char *name)
{
	strlcpy(vm->name, name, VM_MAX_NAME_LEN);
}

void
vm_mgnt_init(void)
{
	secondary_vmids = 0U;
	free_vmids	= secondary_vmids;

	all_vms = vector_init(vm_t *, 1U, 1U);
	if (all_vms == NULL) {
		printf("Error no mem for vm mgnt init");
		exit(1);
	}

	rm_error_t ret = vm_mgnt_new_vm(VMID_HLOS, VMID_RM);
	if (ret != RM_OK) {
		printf("failed to create hlos vm_t");
		exit(1);
	}

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);
	vm_mgnt_set_name(hlos, "HLOS");
}

vm_t *
vm_lookup(vmid_t vmid)
{
	vm_t *ret = NULL;

	size_t cnt = vector_size(all_vms);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm = vector_at_ptr(vm_t *, all_vms, i);
		if ((*vm)->vmid == vmid) {
			ret = *vm;
			break;
		}
	}

	return ret;
}

bool
vm_is_secondary_vm(vmid_t vmid)
{
	uint64_t vmid_bit = (uint64_t)1 << vmid;

	return (secondary_vmids & vmid_bit) != 0;
}

bool
vm_is_peripheral_vm(vmid_t vmid)
{
	uint64_t vmid_bit = (uint64_t)1 << vmid;

	return (peripheral_vmids & vmid_bit) != 0;
}

static bool
is_vm_query_allowed(vm_t *vm, vmid_t client_id)
{
	assert(vm != NULL);

	bool ret = (client_id == vm->vmid) || (client_id == vm->owner);
	if (ret) {
		goto out;
	}

	size_t cnt = vector_size(vm->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **peer_vm = vector_at_ptr(vm_t *, vm->peers, i);
		if ((*peer_vm) == NULL) {
			continue;
		}
		if ((*peer_vm)->vmid == client_id) {
			ret = true;
			goto out;
		}
	}

out:
	return ret;
}

static void
vm_mgnt_handle_get_state(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret;
	vmid_t	   vmid = 0;

	if (len == 4) {
		uint8_t *buf8 = (uint8_t *)buf;
		vmid	      = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);
		if (vmid == 0) {
			vmid = client_id;
		}

		vm_t *vm = vm_lookup(vmid);
		if (vm == NULL) {
			ret = RM_ERROR_NORESOURCE;
			goto out;
		}
		if (!is_vm_query_allowed(vm, client_id)) {
			ret = RM_ERROR_DENIED;
			goto out;
		}

		uint32_t status_ret = vm->vm_state |
				      ((uint32_t)vm->os_state << 8) |
				      ((uint32_t)vm->app_status << 16);

		rm_reply(client_id, msg_id, seq_num, &status_ret, 4);
		ret = RM_OK;
	} else {
		ret = RM_ERROR_MSG_INVALID;
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_set_state(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret = RM_OK;

	if (!vm_is_secondary_vm(client_id)) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (len == 4) {
		os_state_t   os_state;
		app_status_t app_status;

		uint8_t *buf8 = (uint8_t *)buf;

		os_state   = (os_state_t)buf8[1];
		app_status = (app_status_t)buf8[2] |
			     (app_status_t)((app_status_t)buf8[3] << 8);

		vm_t *vm = vm_lookup(client_id);
		if (vm == NULL) {
			ret = RM_ERROR_NORESOURCE;
			goto out;
		}

		// validate arguments
		switch (os_state) {
		case OS_STATE_NONE:
			// treated as no-change
			os_state = vm->os_state;
			break;
		case OS_STATE_EARLY_BOOT:
		case OS_STATE_BOOT:
		case OS_STATE_INIT:
		case OS_STATE_RUN:
		case OS_STATE_SHUTDOWN:
		case OS_STATE_HALTED:
		case OS_STATE_CRASHED:
			break;
		default:
			ret = RM_ERROR_ARGUMENT_INVALID;
			break;
		}
		if (ret != RM_OK) {
			goto out;
		}

		// update statuses
		vm->os_state   = os_state;
		vm->app_status = app_status;

		ret = vm_mgnt_send_state(vm);
		if (ret != RM_OK) {
			printf("error sending update\n");
		}
	} else {
		ret = RM_ERROR_MSG_INVALID;
	}

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_get_type(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			size_t len)
{
	rm_error_t ret;

	if (len != 0) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint32_t host_ret = 0x64 |	    // AArch64
			    (0x1U << 8) |   // Gunyah + RM
			    (0x00U << 16) | // Res 0
			    (0x01U << 24);  // Ver 1

	rm_reply(client_id, msg_id, seq_num, &host_ret, 4);
	ret = RM_OK;

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_get_id(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 4) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid_t	 vmid = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);
	if (vmid == 0) {
		vmid = client_id;
	}

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	if (!is_vm_query_allowed(vm, client_id)) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	// The reply always returns at least the VM's GUID.
	uint32_t id_entries  = 1;
	size_t	 id_msg_size = 12 + VM_GUID_LEN;
	uint16_t id_size;

	size_t name_len	      = vm->name_len;
	size_t name_align_len = util_balign_up(name_len, 4);
	if (name_len != 0) {
		id_entries++;
		id_msg_size += 4 + name_align_len;
	}

	size_t uri_len	     = vm->uri_len;
	size_t uri_align_len = util_balign_up(uri_len, 4);
	if (uri_len != 0) {
		id_entries++;
		id_msg_size += 4 + uri_align_len;
	}

	// add VM signing authority
	const char *sign_auth =
		platform_get_sign_authority_string(vm->signer_info);
	if (sign_auth == NULL) {
		// sign auth is mandatory
		ret = RM_ERROR_VALIDATE_FAILED;
		goto out;
	}

	size_t sign_auth_len	   = strlen(sign_auth);
	size_t sign_auth_align_len = util_balign_up(sign_auth_len, 4);
	id_entries++;
	id_msg_size += 4 + sign_auth_align_len;

	uint8_t *id_msg = calloc(1, id_msg_size);
	if (id_msg == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	buf8 = id_msg;
	ret  = RM_OK;
	memcpy(buf8, &ret, sizeof(rm_error_t));
	buf8 += 4;
	memcpy(buf8, &id_entries, sizeof(uint32_t));
	buf8 += 4;

	*buf8 = VM_ID_TYPE_GUID;
	buf8 += 2;
	id_size = VM_GUID_LEN;
	memcpy(buf8, &id_size, sizeof(uint16_t));
	buf8 += 2;
	memcpy(buf8, vm->guid, VM_GUID_LEN);
	buf8 += VM_GUID_LEN;

	if (name_len != 0) {
		*buf8 = VM_ID_TYPE_NAME;
		buf8 += 2;
		id_size = (uint16_t)name_len;
		memcpy(buf8, &id_size, sizeof(uint16_t));
		buf8 += 2;
		memcpy(buf8, vm->name, name_len);
		buf8 += name_align_len;
	}

	if (uri_len != 0) {
		*buf8 = VM_ID_TYPE_URI;
		buf8 += 2;
		id_size = (uint16_t)uri_len;
		memcpy(buf8, &id_size, sizeof(uint16_t));
		buf8 += 2;
		memcpy(buf8, vm->uri, uri_len);
		buf8 += uri_align_len;
	}

	*buf8 = VM_ID_TYPE_SIGN_AUTH;
	buf8 += 2;
	memcpy(buf8, &sign_auth_len, sizeof(uint16_t));
	buf8 += 2;
	memcpy(buf8, sign_auth, sign_auth_len);
	buf8 += sign_auth_align_len;

	assert((id_msg + id_msg_size) == buf8);

	ret = rm_rpc_fifo_reply(client_id, msg_id, seq_num, id_msg, id_msg_size,
				id_msg_size);
	if (ret != RM_OK) {
		free(id_msg);
		printf("vm_mgnt_handle_get_id: error sending reply %u", ret);
		exit(1);
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static bool
cmp_uri(vm_t *vm, uint8_t *uri, uint16_t uri_len)
{
	return (vm->uri_len == uri_len) && (memcmp(vm->uri, uri, uri_len) == 0);
}

static bool
cmp_guid(vm_t *vm, uint8_t *guid, uint16_t guid_len)
{
	assert(guid_len == VM_GUID_LEN);

	return memcmp(vm->guid, guid, VM_GUID_LEN) == 0;
}

static bool
cmp_name(vm_t *vm, uint8_t *name, uint16_t name_len)
{
	return (vm->name_len == name_len) &&
	       (memcmp(vm->name, name, name_len) == 0);
}

error_t
vm_register_peers(vm_t *vm1, vm_t *vm2)
{
	error_t ret = OK;

	// Add to peer list only if it has not been previously registered
	size_t cnt = vector_size(vm1->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm = vector_at_ptr(vm_t *, vm1->peers, i);
		if ((*vm) == vm2) {
			goto already_registered;
		}
	}

	ret = vector_push_back(vm1->peers, vm2);
	if (ret != OK) {
		ret = RM_ERROR_NOMEM;
		goto err_register;
	}

	ret = vector_push_back(vm2->peers, vm1);
	if (ret != OK) {
		(void)vector_pop_back(vm_t *, vm1->peers);
		ret = RM_ERROR_NOMEM;
		goto err_register;
	}

err_register:
already_registered:
	return ret;
}

void
vm_deregister_all_peers(vm_t *vm)
{
	while (!vector_is_empty(vm->peers)) {
		// Delete peers from VM list
		vm_t  *peer    = NULL;
		vm_t **temp_vm = vector_pop_back(vm_t *, vm->peers);
		if (temp_vm != NULL) {
			peer = *temp_vm;
		}

		if (peer == NULL) {
			continue;
		}

		// Delete VM from peers' list
		size_t cnt = vector_size(peer->peers);
		for (index_t i = 0; i < cnt; i++) {
			vm_t **vm_search =
				vector_at_ptr(vm_t *, peer->peers, i);
			if ((*vm_search) == vm) {
				vector_delete(peer->peers, i);
				break;
			}
		}
	}
}

void
vm_deregister_peers(vm_t *vm1, vm_t *vm2)
{
	size_t cnt = vector_size(vm1->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm_search = vector_at_ptr(vm_t *, vm1->peers, i);
		if ((*vm_search) == vm2) {
			vector_delete(vm1->peers, i);
			break;
		}
	}

	cnt = vector_size(vm2->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm_search = vector_at_ptr(vm_t *, vm2->peers, i);
		if ((*vm_search) == vm1) {
			vector_delete(vm2->peers, i);
			break;
		}
	}
}

vm_t *
vm_lookup_by_id(const char *peer_id)
{
	vm_t *ret = NULL;

	peer_info_t info;
	uint8_t	*id_buf	 = NULL;
	char	     *copy_peer_id = NULL;

	if (peer_id == NULL) {
		printf("Error: Null peer_id for vm_lookup_by_id\n");
		goto out;
	}

	copy_peer_id = strdup(peer_id);
	if (copy_peer_id == NULL) {
		printf("Error: failed to duplicate peer id for lookup\n");
		ret = NULL;
		goto out;
	}

	error_t parse_ret = vm_mgnt_parse_peer_id(copy_peer_id, &info);
	if (parse_ret != OK) {
		printf("Error: failed to parse peer id %s\n", copy_peer_id);
		ret = NULL;
		goto out;
	}

	bool (*id_cmp)(vm_t *, uint8_t *, uint16_t);

	uint8_t	 guid[VM_GUID_LEN];
	uint16_t id_len = 0;

	switch (info.id_type) {
	case VM_ID_TYPE_GUID: {
		error_t parse_guid_ret = parse_guid(info.id_buf, guid);
		if (parse_guid_ret != OK) {
			printf("Error: failed to parse guid from %s\n",
			       info.id_buf);
			ret = NULL;
			goto out;
		}

		id_cmp = cmp_guid;
		id_buf = guid;
		id_len = VM_GUID_LEN;
		break;
	}
	case VM_ID_TYPE_URI:
		id_cmp = cmp_uri;
		id_buf = (uint8_t *)info.id_buf;
		id_len = info.id_len;
		break;
	case VM_ID_TYPE_NAME:
		id_cmp = cmp_name;
		id_buf = (uint8_t *)info.id_buf;
		id_len = info.id_len;
		break;
	case VM_ID_TYPE_SIGN_AUTH:
	default:
		printf("Error: Invalid ID type %d\n", info.id_type);
		goto out;
	}

	size_t cnt = vector_size(all_vms);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm = vector_at_ptr(vm_t *, all_vms, i);
		// in case that guid and uri is optional, the comparison would
		// fail.
		if (id_cmp(*vm, id_buf, id_len)) {
			ret = *vm;
			break;
		}
	}
out:
	free(copy_peer_id);

	return ret;
}

static rm_error_t
vm_mgnt_lookup_by_id(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		     uint8_t *id_buf, uint16_t id_len,
		     bool (*id_cmp)(vm_t *, uint8_t *, uint16_t))
{
	rm_error_t err;
	size_t	   num_vms = vector_size(all_vms);

	assert(id_buf != NULL);

	// Use a bitmap to track matching VMs.
	assert(num_vms < 64);
	uint64_t vm_bitmap = 0;
	uint32_t vm_count  = 0;

	for (index_t i = 0; i < num_vms; i++) {
		vm_t **vm = vector_at_ptr(vm_t *, all_vms, i);

		if (!is_vm_query_allowed(*vm, client_id)) {
			continue;
		}

		if (id_cmp(*vm, id_buf, id_len)) {
			vm_bitmap |= (uint64_t)1 << i;
			vm_count++;
		}
	}

	size_t	 ret_size = 8 + (4 * vm_count);
	uint8_t *ret_buf  = calloc(1, ret_size);
	if (ret_buf == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	uint8_t *buf8 = ret_buf;
	err	      = RM_OK;
	memcpy(buf8, &err, sizeof(rm_error_t));
	buf8 += 4;
	memcpy(buf8, &vm_count, sizeof(uint32_t));
	buf8 += 4;

	while (vm_bitmap != 0) {
		index_t i = compiler_ctz(vm_bitmap);
		vm_bitmap &= ~util_bit(i);

		vm_t **vm = vector_at_ptr(vm_t *, all_vms, i);
		assert(*vm != NULL);

		memcpy(buf8, &(*vm)->vmid, sizeof(vmid_t));
		buf8 += 4;
	}

	assert(buf8 == (ret_buf + ret_size));

	err = rm_rpc_fifo_reply(client_id, msg_id, seq_num, ret_buf, ret_size,
				ret_size);
	if (err != RM_OK) {
		free(ret_buf);
		printf("handle_lookup_by_id: error sending reply %u", err);
		exit(1);
	}
out:
	return err;
}

static void
vm_mgnt_handle_lookup_uri(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			  void *buf, size_t len)
{
	rm_error_t ret;

	if (buf == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (len < 4) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8	 = (uint8_t *)buf;
	uint16_t uri_len = buf8[0] | (uint16_t)((uint16_t)buf8[1] << 8);
	if (uri_len > (VM_MAX_URI_LEN - 1)) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	size_t uri_align_len = util_balign_up(uri_len, 4);
	if ((uri_align_len + 4) != len) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *uri = buf8 + 4;
	uint32_t pad = 0;
	if (memcmp(uri + uri_len, &pad, uri_align_len - uri_len) != 0) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	ret = vm_mgnt_lookup_by_id(client_id, msg_id, seq_num, uri, uri_len,
				   cmp_uri);
out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_lookup_guid(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			   void *buf, size_t len)
{
	rm_error_t ret;

	if (buf == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (len != VM_GUID_LEN) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	ret = vm_mgnt_lookup_by_id(client_id, msg_id, seq_num, (uint8_t *)buf,
				   VM_GUID_LEN, cmp_guid);
out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_lookup_name(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			   void *buf, size_t len)
{
	rm_error_t ret;

	if (buf == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (len < 4) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8	  = (uint8_t *)buf;
	uint16_t name_len = buf8[0] | (uint16_t)((uint16_t)buf8[1] << 8);
	if (name_len > (VM_MAX_NAME_LEN - 1)) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	size_t name_align_len = util_balign_up(name_len, 4);
	if ((name_align_len + 4) != len) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *name = buf8 + 4;
	uint32_t pad  = 0;
	if (memcmp(name + name_len, &pad, name_align_len - name_len) != 0) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	ret = vm_mgnt_lookup_by_id(client_id, msg_id, seq_num, name, name_len,
				   cmp_name);
out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

bool
vm_mgnt_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		    void *buf, size_t len)
{
	bool handled = false;

	if ((client_id == VMID_HYP) && (msg_id != VM_START)) {
		goto out;
	}

	switch (msg_id) {
	case VM_ALLOCATE:
	case VM_DEALLOCATE:
	case VM_SET_NAME:
	case VM_START:
	case VM_STOP:
	case VM_SHUTDOWN:
	case VM_SUSPEND:
	case VM_RESUME:
		// Not supported in v1
		break;
	case VM_GET_STATE:
		vm_mgnt_handle_get_state(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_SET_STATUS:
		vm_mgnt_handle_set_state(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_HOST_GET_TYPE:
		vm_mgnt_handle_get_type(client_id, msg_id, seq_num, len);
		handled = true;
		break;
	case VM_GET_ID:
		vm_mgnt_handle_get_id(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_LOOKUP_URI:
		vm_mgnt_handle_lookup_uri(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_LOOKUP_GUID:
		vm_mgnt_handle_lookup_guid(client_id, msg_id, seq_num, buf,
					   len);
		handled = true;
		break;
	case VM_LOOKUP_NAME:
		vm_mgnt_handle_lookup_name(client_id, msg_id, seq_num, buf,
					   len);
		handled = true;
		break;
	default:
		break;
	}

out:
	return handled;
}

error_t
parse_guid(const char *guid_string, uint8_t guid[VM_GUID_LEN])
{
	error_t ret = OK;

	unsigned int tmp[8];

	int num_in = sscanf(guid_string, "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
			    &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4],
			    &tmp[5], &tmp[6], &tmp[7]);
	if (num_in != 8) {
		ret = ERROR_ARGUMENT_SIZE;
		goto out;
	}

	for (int i = 0; i < 8; i++) {
		uint16_t be16 = htobe16((uint16_t)tmp[i]);
		memcpy(guid + (i * 2), &be16, 2);
	}
out:
	return ret;
}

error_t
vm_mgnt_parse_peer_id(char *peer_id, peer_info_t *info)
{
	error_t ret    = OK;
	char   *id_val = NULL;

	if (peer_id == NULL) {
		printf("Error: Null peer_id to parse\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (info == NULL) {
		printf("Error: Null info to parse peer id\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// Check which lookup id has been specified (guid, name, or uri)
	char *id = strtok_r(peer_id, ":", &id_val);
	if (id == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (strcmp(id, "vm-guid") == 0) {
		info->id_type = VM_ID_TYPE_GUID;
	} else if (strcmp(id, "vm-name") == 0) {
		info->id_type = VM_ID_TYPE_NAME;
	} else if (strcmp(id, "vm-uri") == 0) {
		info->id_type = VM_ID_TYPE_URI;
	} else {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	assert(id_val != NULL);
	info->id_buf = id_val;
	info->id_len = (uint16_t)strlen(id_val);

	ret = OK;

out:
	return ret;
}

bool
vm_mgnt_is_vm_sensitive(vmid_t vmid)
{
	bool ret;

	// assume RM is sensitive VM
	if (vmid == VMID_RM) {
		ret = true;
		goto out;
	}

	// should find the VM
	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	ret = vm->sensitive;
out:
	return ret;
}
