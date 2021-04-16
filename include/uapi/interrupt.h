// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define IRQ_MAGIC 0x49

#define IOCTL_ENABLE_IRQ      _IOW(IRQ_MAGIC, 0, int)
#define IOCTL_DISABLE_IRQ     _IOW(IRQ_MAGIC, 1, int)
#define IOCTL_REGISTER_ISR    _IOW(IRQ_MAGIC, 2, struct register_isr_req)
#define IOCTL_SET_IRQ_TRIGGER _IOW(IRQ_MAGIC, 3, struct irq_set_trigger_req)
#define IOCTL_DEREGISTER_ISR  _IOW(IRQ_MAGIC, 4, int)

typedef bool (*isr_t)(int, void *);

struct register_isr_req {
	isr_t isr;
	int   irq;
	int   res0;
	void *data;
};

#define IRQ_TRIGGER_LEVEL_HIGH	 0
#define IRQ_TRIGGER_LEVEL_LOW	 1
#define IRQ_TRIGGER_EDGE_RISING	 2
#define IRQ_TRIGGER_EDGE_FALLING 3
#define IRQ_TRIGGER_EDGE_BOTH	 4
#define IRQ_TRIGGER_MESSAGE	 5

struct irq_set_trigger_req {
	int irq;
	int trigger;
};
