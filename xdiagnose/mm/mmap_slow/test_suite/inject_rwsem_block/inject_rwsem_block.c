/*
	故障注入工具。配合 daemon 用户态测试程序一起使用。
	遍历系统所有进程，找到 daemon 进程，获取其 mm->mmap_sem 锁。注入指定 ns（秒）读或者写锁持有时间，然后再释放。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define LOG_PFX		"======== [inject]"

static unsigned int lr = 0;

static unsigned int ns = 10;

#define DR		(0x1)
#define DR_TRY	(DR | 0x2)
static unsigned int ro = 0;

static unsigned int urm = 1;

static unsigned long dms = 1000;

static char *proc = "daemon";

static void delay_rwsem_unlock(struct work_struct *work);
static DECLARE_DELAYED_WORK(rwsem_unlock_dw, delay_rwsem_unlock);

static struct rw_semaphore *g_sem;

static void delay_rwsem_unlock(struct work_struct *work)
{
	char *comm = current->comm;
	pid_t tgid = current->tgid;

	pr_info(LOG_PFX"[cpu%d][%s][%5d] enter\n", smp_processor_id(), comm, tgid);
	if (g_sem) {
		down_read(g_sem);
		pr_info(LOG_PFX"[cpu%d][%s][%5d] down_read done (sem: 0x%lx)\n", smp_processor_id(), comm, tgid, (unsigned long)g_sem);
		msleep(5000);
		up_read(g_sem);
		pr_info(LOG_PFX"[cpu%d][%s][%5d] up_read done\n", smp_processor_id(), comm, tgid);
	}
	else {
		pr_info(LOG_PFX"[cpu%d][%s][%5d] g_sem is NULL\n", smp_processor_id(), comm, tgid);
	}
	pr_info(LOG_PFX"[cpu%d][%s][%5d] leave\n", smp_processor_id(), comm, tgid);
}

static void dr_drtry_ur(void)
{
	int i;
	char *comm = current->comm;
	pid_t tgid = current->tgid;
	int ret;
	schedule_delayed_work(&rwsem_unlock_dw, msecs_to_jiffies(dms));
	
	down_read(g_sem);
	pr_info(LOG_PFX"[cpu%d][%s][%5d] down_read done (sem: 0x%lx)\n", smp_processor_id(), comm, tgid, (unsigned long)g_sem);

	pr_info(LOG_PFX"[cpu%d][%s][%5d] down_read_trylock\n", smp_processor_id(), comm, tgid);
	ret = down_read_trylock(g_sem);
	pr_info(LOG_PFX"[cpu%d][%s][%5d] down_read_trylock return(%s)\n",
			smp_processor_id(), comm, tgid, ret == 1 ? "successful" : (ret == 0 ? "contention" : "???"));

	pr_info(LOG_PFX"[cpu%d][%s][%5d] will msleep: %u s\n", smp_processor_id(), comm, tgid, ns);
	for (i = 0; i < ns; i++) {
		msleep(1000);
	}

	/* !!! should call one more up_read for down_read_trylock */
	if (urm && ret) {
		up_read(g_sem);
		pr_info(LOG_PFX"[cpu%d][%s][%5d] up_read for down_read_trylock\n", smp_processor_id(), comm, tgid);
	}
	up_read(g_sem);
	pr_info(LOG_PFX"[cpu%d][%s][%5d] up_read done\n", smp_processor_id(), comm, tgid);
}

static void dw_drtry_uw(void)
{
	int i;
	char *comm = current->comm;
	pid_t tgid = current->tgid;
	int ret;
	schedule_delayed_work(&rwsem_unlock_dw, msecs_to_jiffies(dms));

	down_write(g_sem);
	pr_info(LOG_PFX"[cpu%d][%s][%5d] down_write done (sem: 0x%lx)\n", smp_processor_id(), comm, tgid, (unsigned long)g_sem);

	pr_info(LOG_PFX"[cpu%d][%s][%5d] down_read_trylock\n", smp_processor_id(), comm, tgid);
	ret = down_read_trylock(g_sem);
	pr_info(LOG_PFX"[cpu%d][%s][%5d] down_read_trylock return(%s)\n",
			smp_processor_id(), comm, tgid, ret == 1 ? "successful" : (ret == 0 ? "contention" : "???"));
	/* no need call up_read for down_read_trylock, we expect it return contention */

	pr_info(LOG_PFX"[cpu%d][%s][%5d] will msleep: %u s\n", smp_processor_id(), comm, tgid, ns);
	for (i = 0; i < ns; i++) {
		msleep(1000);
	}

	up_write(g_sem);
	pr_info(LOG_PFX"[cpu%d][%s][%5d] up_write done\n", smp_processor_id(), comm, tgid);
}

static void loop_rsem(void)
{
	int i;
	char *comm = current->comm;
	pid_t tgid = current->tgid;

	for (i = 0; i < lr; i++) {
		down_read(g_sem);
		pr_info(LOG_PFX"[cpu%d][%s][%5d] down_read done(%d) (sem: 0x%lx)\n", smp_processor_id(), comm, tgid, i, (unsigned long)g_sem);
	}
	
	msleep(20000);
	
	for (i = 0; i < lr; i++) {
		up_read(g_sem);
		pr_info(LOG_PFX"[cpu%d][%s][%5d]  up_read  done(%d) (sem: 0x%lx)\n", smp_processor_id(), comm, tgid, i, (unsigned long)g_sem);
		msleep(2000);
	}
}

static void run_test_case(void)
{
	if (g_sem) {
		if (lr) {
			loop_rsem();
		} else {
			if (ro == DR) {
				dr_drtry_ur();
			} else if (ro == DR_TRY) {
				return;
			} else {
				dw_drtry_uw();
			}
			pr_info(LOG_PFX"[cpu%d][%s][%5d] will msleep 10000 ms\n", smp_processor_id(), current->comm, current->tgid);
			msleep(10000);
			pr_info(LOG_PFX"[cpu%d][%s][%5d] run_test_case done\n", smp_processor_id(), current->comm, current->tgid);	
		}
	}
}

static int find_task(void)
{
	struct task_struct *p;	
	int ret = 0;

	rcu_read_lock();
	for_each_process(p) {
		if (0 == strcmp(p->comm, proc)) {
			pr_info(LOG_PFX"[cpu%d][%s][%5d] task found\n", smp_processor_id(), p->comm, p->tgid);
			g_sem = &p->mm->mmap_sem;
			goto out;
		}
	}

	pr_err(LOG_PFX"[cpu%d][%s][%5d] task not found\n", smp_processor_id(), p->comm, p->tgid);
	ret = -EINVAL;
out:
	rcu_read_unlock();
	run_test_case();
	return ret;
}

static int __init inject_rwsem_block_init(void)
{
	return (find_task());
}

static void __exit inject_rwsem_block_exit(void)
{
    pr_info("%s\n", __FUNCTION__);
}

module_init(inject_rwsem_block_init)
module_exit(inject_rwsem_block_exit)
MODULE_LICENSE("GPL");
