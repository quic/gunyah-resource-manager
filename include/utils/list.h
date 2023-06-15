// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// append to the tail of the list
#define list_append(type, headp, node, prefix)                                 \
	do {                                                                   \
		type **_headp = (headp);                                       \
		type  *_node  = (node);                                        \
		if (*_headp == NULL) {                                         \
			_node->prefix##next = NULL;                            \
			_node->prefix##prev = _node;                           \
			*_headp		    = _node;                           \
		} else {                                                       \
			type *_tail		= (*_headp)->prefix##prev;     \
			_node->prefix##next	= NULL;                        \
			_node->prefix##prev	= _tail;                       \
			_tail->prefix##next	= _node;                       \
			(*_headp)->prefix##prev = _node;                       \
		}                                                              \
	} while (0)

#define list_append_list(type, to_headp, from_headp, prefix)                   \
	do {                                                                   \
		type **_from_headp = (from_headp);                             \
		type **_to_headp   = (to_headp);                               \
		if (*_to_headp == NULL) {                                      \
			*_to_headp = *_from_headp;                             \
		} else {                                                       \
			type *_from_tail       = (*_from_headp)->prefix##prev; \
			type *_to_tail	       = (*_to_headp)->prefix##prev;   \
			_to_tail->prefix##next = (*_from_headp);               \
			(*_from_headp)->prefix##prev = _to_tail;               \
			(*_to_headp)->prefix##prev   = _from_tail;             \
		}                                                              \
	} while (0)

#define list_insert_head(type, headp, node, prefix)                            \
	do {                                                                   \
		type **_headp = (headp);                                       \
		type  *_node  = (node);                                        \
		if (*_headp == NULL) {                                         \
			_node->prefix##next = NULL;                            \
			_node->prefix##prev = _node;                           \
			*_headp		    = _node;                           \
		} else {                                                       \
			assert(*_headp != NULL);                               \
			type *_tail		= (*_headp)->prefix##prev;     \
			_node->prefix##prev	= _tail;                       \
			_node->prefix##next	= *_headp;                     \
			(*_headp)->prefix##prev = _node;                       \
			*_headp			= _node;                       \
		}                                                              \
	} while (0)

// insert after current node in list
#define list_insert_after(type, headp, curr, node, prefix)                     \
	do {                                                                   \
		type **_headp = (headp);                                       \
		type  *_curr  = (curr);                                        \
		type  *_node  = (node);                                        \
		assert(_curr != NULL);                                         \
		type *_next	    = (_curr->prefix##next);                   \
		_node->prefix##next = _next;                                   \
		_node->prefix##prev = _curr;                                   \
		_curr->prefix##next = _node;                                   \
		if (_next != NULL) {                                           \
			_next->prefix##prev = _node;                           \
		}                                                              \
		if (curr == (*_headp)->prefix##prev) {                         \
			(*_headp)->prefix##prev = _node;                       \
		}                                                              \
	} while (0)

// remove specified node from the list
#define list_remove(type, headp, node, prefix)                                 \
	do {                                                                   \
		type **_headp = (headp);                                       \
		type  *_node  = (node);                                        \
		type  *_next  = _node->prefix##next;                           \
		type  *_prev  = _node->prefix##prev;                           \
		if (_next) {                                                   \
			_next->prefix##prev = _prev;                           \
		}                                                              \
		if (_prev && (*_headp != _node)) {                             \
			_prev->prefix##next = _next;                           \
		}                                                              \
		if (*_headp == _node) {                                        \
			*_headp = (_prev == _node) ? NULL : _next;             \
		} else if ((*_headp)->prefix##prev == _node) {                 \
			(*_headp)->prefix##prev = _prev;                       \
		}                                                              \
	} while (0)

// loop list
#define loop_list(node, headp, prefix)                                         \
	for (node = *headp; node != NULL; node = node->prefix##next)

// loop list, allowed deletion in the loop
#define loop_list_safe(node, next_node, headp, prefix)                         \
	for (node		= *headp,                                      \
	    next_node		= (node != NULL) ? node->prefix##next : NULL;  \
	     node != NULL; node = next_node,                                   \
	    next_node		= (node != NULL) ? node->prefix##next : NULL)

// check if list is empty
#define is_empty(head)		     ((head) == NULL)
#define is_first(node, head, prefix) ((node) == (head))
#define is_last(node, prefix)	     (node->prefix##next == NULL)
#define list_tail(head, prefix)	     ((head)->prefix##prev)
#define list_prev(node, head, prefix)                                          \
	(is_first(node, head, prefix) ? NULL : node->prefix##prev)
