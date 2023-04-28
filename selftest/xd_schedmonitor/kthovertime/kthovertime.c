#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/delay.h>

static struct task_struct *kthreadp;

static int kthovertime_fn(void *data)
{
	unsigned int i, cpu;
	pr_info("kthovertime_fn started\n");
	while(!kthread_should_stop()){
		pr_info(":::::start, cpu=%d\n", smp_processor_id());
		i = 0;
		while(i < 500*1000*1000){
			cpu = smp_processor_id();
			if(cpu == i)
				i++;
			i++;
		}
		pr_info(":::::end cpu=%d\n", smp_processor_id());
		cond_resched();
		msleep(1000);
	}
	pr_info("kthovertime_fn end\n");
	return 0;
}

static int __init kthovertime_init(void)
{
	kthreadp = kthread_run(kthovertime_fn, NULL, "kthovertime");
	if(!kthreadp){
		pr_info("kthovertime kthread_run failed\n");
		return -1;
	}
	pr_info("kthovertime mod INIT finished\n");
	return 0;
}

static void __exit kthovertime_exit(void)
{
	if(kthreadp){
		kthread_stop(kthreadp);
		kthreadp = NULL;
		pr_info("kthovertime kthread stopped\n");
	}
	pr_info("kthovertime mod EXIT\n");
}

module_init(kthovertime_init)
module_exit(kthovertime_exit)
MODULE_LICENSE("GPL");
