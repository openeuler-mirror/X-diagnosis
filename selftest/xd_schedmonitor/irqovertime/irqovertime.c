#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#include <linux/irq.h>
#include <linux/interrupt.h>

/* irq number for injection, need modify */
#define INJECT_IRQ_VEC $IRQNUM /* need reassign the value */

#define MAX_SYMBOL_LEN	64
static char sym_irq[MAX_SYMBOL_LEN] = "hns_irq_handle";
module_param_string(sym_irq, sym_irq, sizeof(sym_irq), 0644);

static struct kprobe kp = {
	.symbol_name	= sym_irq,
};

static int __kprobes irq_inject(struct kprobe *p, struct pt_regs *regs)
{
	int i, j;
	unsigned int irq;

#ifdef CONFIG_ARM64
	irq = (unsigned int)regs->regs[0];
#endif
#ifdef CONFIG_X86
	irq = (unsigned int)regs->di;
#endif
	if(irq == INJECT_IRQ_VEC){
		printk(":::start::: irq:%d\n", irq);
		for(i = 0; i < 10000; i++)
			for(j = 0; j < 10000; j++)
				if(i == j)
					j++;
		printk(":::end:::\n");
	}
	return 0;
}

static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
	return;
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	return 0;
}
/* NOKPROBE_SYMBOL() is also available */
NOKPROBE_SYMBOL(handler_fault);

static int __init irqovertime_init(void)
{
	int ret;
	/* register kprobe for irq handler */
	kp.pre_handler = irq_inject;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}

	/* start a kernel thread */
	pr_info("irqovertime mod INIT finished\n");
	return 0;
}

static void __exit irqovertime_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("irqovertime mod EXIT\n");
}

module_init(irqovertime_init)
module_exit(irqovertime_exit)
MODULE_LICENSE("GPL");
