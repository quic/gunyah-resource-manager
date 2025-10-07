// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef UTILS_LIST_H_
#define UTILS_LIST_H_

// append to the tail of the list
#define list_append(type, headp, node, prefix)                                 \
	do {                                                                   \
		if (*(headp) == NULL) {                                        \
			(node)->prefix##next = NULL;                           \
			(node)->prefix##prev = (node);                         \
			*(headp)	     = (node);                         \
		} else {                                                       \
			type *tail__p		 = (*(headp))->prefix##prev;   \
			(node)->prefix##next	 = NULL;                       \
			(node)->prefix##prev	 = tail__p;                    \
			tail__p->prefix##next	 = (node);                     \
			(*(headp))->prefix##prev = (node);                     \
		}                                                              \
	} while (0)

#define list_append_list(type, to_headp, from_headp, prefix)                    \
	do {                                                                    \
		if (*(to_headp) == NULL) {                                      \
			*(to_headp) = *(from_headp);                            \
		} else {                                                        \
			type *from__tail       = (*(from_headp))->prefix##prev; \
			type *to__tail	       = (*(to_headp))->prefix##prev;   \
			to__tail->prefix##next = *(from_headp);                 \
			(*(from_headp))->prefix##prev = to__tail;               \
			(*(to_headp))->prefix##prev   = from__tail;             \
		}                                                               \
	} while (0)

#define list_insert_head(type, headp, node, prefix)                            \
	do {                                                                   \
		if (*(headp) == NULL) {                                        \
			(node)->prefix##next = NULL;                           \
			(node)->prefix##prev = (node);                         \
			*(headp)	     = (node);                         \
		} else {                                                       \
			assert(*(headp) != NULL);                              \
			type *tail__p		 = (*(headp))->prefix##prev;   \
			(node)->prefix##prev	 = tail__p;                    \
			(node)->prefix##next	 = *(headp);                   \
			(*(headp))->prefix##prev = (node);                     \
			*(headp)		 = (node);                     \
		}                                                              \
	} while (0)

// insert after current node in list
#define list_insert_after(type, headp, curr, node, prefix)                     \
	do {                                                                   \
		assert((curr) != NULL);                                        \
		type *c__next	     = (curr)->prefix##next;                   \
		(node)->prefix##next = c__next;                                \
		(node)->prefix##prev = (curr);                                 \
		(curr)->prefix##next = (node);                                 \
		if (c__next != NULL) {                                         \
			c__next->prefix##prev = (node);                        \
		}                                                              \
		if ((curr) == (*(headp))->prefix##prev) {                      \
			(*(headp))->prefix##prev = (node);                     \
		}                                                              \
	} while (0)

// remove specified node from the list
#define list_remove(type, headp, node, prefix)                                 \
	do {                                                                   \
		type *n__next = (node)->prefix##next;                          \
		type *n__prev = (node)->prefix##prev;                          \
		assert(*(headp) != NULL);                                      \
		assert(n__prev != NULL);                                       \
		if (n__next != NULL) {                                         \
			n__next->prefix##prev = n__prev;                       \
		}                                                              \
		if (*(headp) == (node)) {                                      \
			*(headp) = (n__prev == (node)) ? NULL : n__next;       \
		} else {                                                       \
			n__prev->prefix##next = n__next;                       \
			if ((*(headp))->prefix##prev == (node)) {              \
				(*(headp))->prefix##prev = n__prev;            \
			}                                                      \
		}                                                              \
	} while (0)

// loop list
#define loop_list(node, headp, prefix)                                         \
	for ((node) = *(headp); (node) != NULL; (node) = (node)->prefix##next)

// loop list, allowed deletion in the loop
#define loop_list_safe(node, next_node, headp, prefix)                         \
	(node)	    = *(headp);                                                \
	(next_node) = ((node) != NULL) ? (node)->prefix##next : NULL;          \
	for (; (node) != NULL;                                                 \
	     (node)	 = (next_node),                                        \
	     (next_node) = ((node) != NULL) ? (node)->prefix##next : NULL)

// check if list is empty
#define is_empty(head)		     ((head) == NULL)
#define is_first(node, head, prefix) ((node) == (head))
#define is_last(node, prefix)	     ((node)->prefix##next == NULL)
#define list_tail(head, prefix)	     ((head)->prefix##prev)
#define list_prev(node, head, prefix)                                          \
	(is_first((node), (head), (prefix)) ? NULL : (node)->prefix##prev)

#else

#error multiple include of utils/list.h

#endif
