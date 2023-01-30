#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/rtnetlink.h>
#include <linux/kernel.h>

#define ENTER() printk(KERN_DEBUG "%s() Enter", __func__)
#define EXIT() printk(KERN_DEBUG "%s() Exit", __func__)
#define ERR(fmt, args...) printk(KERN_ERR "%s()-%d " fmt "\n", __func__, __LINE__, ##args)
#define DBG(fmt, args...) printk(KERN_DEBUG "%s()-%d " fmt "\n", __func__, __LINE__, ##args)

static struct task_struct *test_kthread = NULL;

static int kthread_test_func(void *data)
{
	ENTER();
	while (!kthread_should_stop()) {
		long i = 0;
		DBG("rtnl_lock");
		rtnl_lock();
		while (i < 20000000000) {
			smp_processor_id();
			++i;
		}
		rtnl_unlock();
		DBG("rtnl_unlock");

		msleep(1000);
	}

	EXIT();
	return 0;
}

static __init int kthread_test_init(void)
{
	ENTER();
	test_kthread = kthread_run(kthread_test_func, NULL, "kthread-test");
	if (!test_kthread) {
		ERR("kthread_run fail");
		return -ECHILD;
	}

	EXIT();
	return 0;
}

static __exit void kthread_test_exit(void)
{
	ENTER();
	if (test_kthread) {
		DBG("kthread_stop");
		kthread_stop(test_kthread);
		test_kthread = NULL;
	}

	EXIT();
}

module_init(kthread_test_init);
module_exit(kthread_test_exit);
MODULE_LICENSE("GPL");
