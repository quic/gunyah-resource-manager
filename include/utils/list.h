// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// append to the tail of the list
#define list_append(type, head, node, prefix)                                  \
	do {                                                                   \
		type **_head = (head);                                         \
		type  *_node = (node);                                         \
		if (*_head == NULL) {                                          \
			_node->prefix##next = NULL;                            \
			_node->prefix##prev = _node;                           \
			*_head		    = _node;                           \
		} else {                                                       \
			type *_tail	       = (*_head)->prefix##prev;       \
			_node->prefix##next    = NULL;                         \
			_node->prefix##prev    = _tail;                        \
			_tail->prefix##next    = _node;                        \
			(*_head)->prefix##prev = _node;                        \
		}                                                              \
	} while (0)

#define list_insert_head(type, head, node, prefix)                             \
	do {                                                                   \
		type **_head = (head);                                         \
		type  *_node = (node);                                         \
		assert(*_head != NULL);                                        \
		type *_tail	       = (*_head)->prefix##prev;               \
		_node->prefix##prev    = _tail;                                \
		_node->prefix##next    = *_head;                               \
		(*_head)->prefix##prev = _node;                                \
		*_head		       = _node;                                \
	} while (0)

// insert after current node in list
#define list_insert_after(type, head, curr, node, prefix)                      \
	do {                                                                   \
		type **_head = (head);                                         \
		type  *_curr = (curr);                                         \
		type  *_node = (node);                                         \
		assert(_curr != NULL);                                         \
		type *_next	    = (_curr->prefix##next);                   \
		_node->prefix##next = _next;                                   \
		_node->prefix##prev = _curr;                                   \
		_curr->prefix##next = _node;                                   \
		if (_next != NULL) {                                           \
			_next->prefix##prev = _node;                           \
		}                                                              \
		if (curr == (*_head)->prefix##prev) {                          \
			(*_head)->prefix##prev = _node;                        \
		}                                                              \
	} while (0)

// remove specified node from the list
#define list_remove(type, head, node, prefix)                                  \
	do {                                                                   \
		type **_head = (head);                                         \
		type  *_node = (node);                                         \
		type  *_next = _node->prefix##next;                            \
		type  *_prev = _node->prefix##prev;                            \
		if (_next) {                                                   \
			_next->prefix##prev = _prev;                           \
		}                                                              \
		if (_prev && (*_head != _node)) {                              \
			_prev->prefix##next = _next;                           \
		}                                                              \
		if (*_head == _node) {                                         \
			*_head = (_prev == _node) ? NULL : _next;              \
		} else if ((*_head)->prefix##prev == _node) {                  \
			(*_head)->prefix##prev = _prev;                        \
		}                                                              \
	} while (0)

// loop list
#define loop_list(node, head, prefix)                                          \
	for (node = *head; node != NULL; node = node->prefix##next)

// loop list, allowed deletion in the loop
#define loop_list_safe(node, next_node, head, prefix)                          \
	for (node		= *head,                                       \
	    next_node		= (node != NULL) ? node->prefix##next : NULL;  \
	     node != NULL; node = next_node,                                   \
	    next_node		= (node != NULL) ? node->prefix##next : NULL)

// check if list is empty
#define is_empty(head)		     (head == NULL)
#define is_first(node, head, prefix) (node == *head)
#define is_last(node, prefix)	     (node->prefix##next == NULL)
