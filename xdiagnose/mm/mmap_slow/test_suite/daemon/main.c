/*
编译方式:
gcc -o daemon main.c -lpthread -g

第1个参数: g_sleep 		控制线程执行周期内睡眠时间单位是秒
第2个参数: g_cpu_num 	控制创建线程个数

测试程序的功能：
配合 inject_rwsem_block 驱动一起使用，测试读写锁对 mmap 的影响。
创建 g_cpu_num 个线程，线程执行 mmap/munmap/sleep 。

 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/mman.h>

int g_sleep = 3;
int g_cpu_num = 0;
int g_dyn = 0;
int debug = 0;
unsigned int ttms = 300;

#define MMAP_SIZE_4K (1024 * 4096)
#define SEC_TO_US (1000000)
#define SEC_TO_MS (1000)

struct thread_manager {
	pthread_t t;
};
static struct thread_manager *tm = NULL;

static pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

static long calc_timeval_diff(struct timeval *s, struct timeval *e)
{
	long start, end, diff_ms;

	start = s->tv_sec * SEC_TO_US + s->tv_usec;
	end = e->tv_sec * SEC_TO_US + e->tv_usec;
	diff_ms = (end - start) / SEC_TO_MS;
	return diff_ms;
}

void *dynamic_fn(void *arg)
{
	int num = (int)arg;
	struct timeval start, end;
	char tname[16];
	memset(tname, 0x0, sizeof(tname));
	sprintf(tname, "dynamic_%d", num);
	prctl(PR_SET_NAME, tname);

	gettimeofday(&start, NULL);
	sleep(1);
	gettimeofday(&end, NULL);

	printf("         [%ld.%ld][thread:%2d][%6d:%s:%6d] ran %ld ms\n",
		end.tv_sec, end.tv_usec, num, getpid(), tname, gettid(),
		calc_timeval_diff(&start, &end));
	return NULL;
}

static void dynamic_threads(void)
{
	const int tn = 4;
	int i, rc;
	pthread_t ta[4];

	while (1) {
		for (i = 0; i < tn; i++) {
			rc = pthread_create(&ta[i], NULL, dynamic_fn, (void *)i);
			if (rc) {
				printf("         [thread:%2d] create dynamic threads failed. %s\n", i, strerror(errno));
				ta[i] = 0;
				sleep(2);
				continue;
			}
		}
		sleep(4);
		for (i = 0; i < tn; i++) {
			if (ta[i])
				pthread_join(ta[i], NULL);
		}
	}
}

static void mmap_thread(const int num)
{
	void *pmap = NULL;
	struct timeval start, end, sleeptime, umap_start, umap_end;
	long diff_ms;
	char tname[16];
	
	memset(tname, 0x0, sizeof(tname));
	sprintf(tname, "mmap_%d", num);
	prctl(PR_SET_NAME, tname);
	sleep(2);
	printf("[thread:%2d][%6d:%s:%6d] start to run\n" , num, getpid(), tname, gettid());
	sleep(2);

	while (1) {
		if (0 != gettimeofday(&start, NULL)) {
			printf("[thread:%2d] start gettimeofday failed. %s\n", num, strerror(errno));
			continue;
		}

		pmap = mmap(NULL, MMAP_SIZE_4K, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (MAP_FAILED == pmap) {
			printf("[thread:%2d] mmap failed, length: %d. %s\n", num, MMAP_SIZE_4K, strerror(errno));
			continue;
		}

		if (0 != gettimeofday(&end, NULL)) {
			printf("[thread:%2d] end gettimeofday failed. %s\n", num, strerror(errno));
			goto unmap;
		}

		if (debug) {
			printf("[%ld.%ld][thread:%2d][%6d:%s:%6d] begin  to mmap\n",
				start.tv_sec, start.tv_usec, num, getpid(), tname, gettid());
			printf("[%ld.%ld][thread:%2d][%6d:%s:%6d] finish to mmap\n",
				end.tv_sec, end.tv_usec, num, getpid(), tname, gettid());
		}

		diff_ms = calc_timeval_diff(&start, &end);
		if (diff_ms > ttms) {
			printf("[%ld.%ld][thread:%2d][%6d:%s:%6d] mmap cost too long(%ld ms)\n",
				end.tv_sec, end.tv_usec, num, getpid(), tname, gettid(), diff_ms);
		}

unmap:
		gettimeofday(&umap_start, NULL);

		if (0 != munmap(pmap, MMAP_SIZE_4K)) {
			printf("[thread:%2d] munmap failed. %s\n", num, strerror(errno));
		}

		gettimeofday(&umap_end, NULL);

		if (debug) {
			printf("[%ld.%ld][thread:%2d][%6d:%s:%6d] begin  to munmap\n",
				umap_start.tv_sec, umap_start.tv_usec, num, getpid(), tname, gettid());
			printf("[%ld.%ld][thread:%2d][%6d:%s:%6d] finish to munmap\n",
				umap_end.tv_sec, umap_end.tv_usec, num, getpid(), tname, gettid());
		}

		diff_ms = calc_timeval_diff(&umap_start, &umap_end);
		if (diff_ms > ttms) {
			printf("[%ld.%ld][thread:%2d][%6d:%s:%6d] munmap cost too long(%ld ms)\n",
					end.tv_sec, end.tv_usec, num, getpid(), tname, gettid(), diff_ms);
		}

		if (g_sleep > 0)
			sleep(g_sleep);
		else if (g_sleep == 0)
			goto out;

		gettimeofday(&sleeptime, NULL);
		if (debug)
			printf("[%ld.%ld][thread:%2d][%6d:%s:%6d] sleep over\n",
				sleeptime.tv_sec, sleeptime.tv_usec, num, getpid(), tname, gettid());
	}
out:
	printf("[thread:%2d][%6d:%s:%6d] exit\n" , num, getpid(), tname, gettid());
}

void *thread_fn(void *arg)
{
	int num = (int)arg;

	if (g_dyn && 0 == num) {
		dynamic_threads();
	} else {
		mmap_thread(num);
	}

	return NULL;
}

void main(int argc, char **argv)
{
	int rc;
	int i;
	const int NUM_THREADS = 4;

	if (argc >= 2)
		g_sleep = atoi(argv[1]);
	if (argc >= 3)
		g_cpu_num = atoi(argv[2]);
	if (argc >= 4)
		g_dyn = atoi(argv[3]);

	if (0 == g_cpu_num) {
		g_cpu_num = sysconf(_SC_NPROCESSORS_CONF);
		if (g_cpu_num <= 0)
			g_cpu_num = NUM_THREADS;
	}
	g_cpu_num++;

	printf("[pid: %6d][tid: %6d] cpu num: %d, sleep: %d(s), g_dyn: %d\n",
			getpid(), gettid(), g_cpu_num, g_sleep, g_dyn);

	tm = (struct thread_manager *)malloc(sizeof(struct thread_manager) * g_cpu_num);
	if (!tm) {
		printf("malloc failed. %s\n", strerror(errno));
		return;
	}

	while (1) {
		for (i = 0; i < g_cpu_num; i++) {
			rc = pthread_create(&(tm[i].t), NULL, thread_fn, (void *)i);
			if (rc) {
				printf("[%2d] pthread_create failed. %s\n", i, strerror(errno));
				return;
			}
			printf("[thread:%2d][%6d:%6d] create success\n", i, getpid(), gettid());
		}

		sleep(2);

		for (i = 0; i < g_cpu_num; i++) {
			pthread_join(tm[i].t, NULL);
		}
	}

	return;
}
