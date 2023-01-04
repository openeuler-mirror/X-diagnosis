/*
	mm_populate test case
*/
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/prctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>

#define MAP_SIZE (128 * 1024 * 1024)
#define SEC_TO_US 	(1000000)
#define MS_TO_US 	(1000)

#define ACT_POP		0x4
#define ACT_WRITE	0x1
#define ACT_READ	0x2
#define ACT_MLOCK	0x8
#define ACT_MEMSET	0x10

static int g_act = 0;
static int g_cpu_num = 0;
static int g_debug = 0;

static int ready_go = 0;
static int show_stat = 0;
pthread_mutex_t stat_lock = PTHREAD_MUTEX_INITIALIZER;

static long mmap_cost_max = 0;
static long act_cost_max = 0;
static long memset_cost_max = 0;
static unsigned long mmap_cost_total = 0;
static unsigned long act_cost_total = 0;
static unsigned long memset_cost_total = 0;

#define max(a, b) ((a) > (b) ? (a) : (b))

static pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

static long time_diff(struct timeval *s, struct timeval *e)
{
	long start, end, diff_ms;
	start = s->tv_sec * SEC_TO_US + s->tv_usec;
	end = e->tv_sec * SEC_TO_US + e->tv_usec;
	diff_ms = (end - start) / MS_TO_US;
	return diff_ms;
}

static void set_new_name(int cpu)
{
	char name[16];
	
	memset(name, 0x0, sizeof(name));
	sprintf(name, "aqua_%d", cpu);
	prctl(PR_SET_NAME, name);
}

static void bind_cpu(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);

	if (sched_setaffinity(0, sizeof(mask), &mask))
		printf("[%3d] sched_setaffinity failed. %s\n", cpu, strerror(errno));

	return;
}

static void do_mmap(int cpu)
{
	int fd;
	int i;
	int flags = 0;
	void *pmap;
	struct timeval s1, s2, s3, s4;
	char shm_file[8];
	char *act = "no act";
	long mmap_cost;
	long act_cost;
	long memset_cost;
	
	memset(shm_file, 0x0, sizeof(shm_file));
	sprintf(shm_file, "shm%d", cpu);
	
	fd = shm_open(shm_file, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
        printf("[%3d][%6d:%6d] shm_open failed. %s\n",
				cpu, getpid(), gettid(), strerror(errno));
        exit(1);
    }

	if (ftruncate(fd, MAP_SIZE) < 0) {
        printf("[%3d][%6d:%6d] ftruncate failed. %s\n",
				cpu, getpid(), gettid(), strerror(errno));
        exit(1);
    }

	if (g_act & ACT_POP)
		flags = MAP_POPULATE;

	gettimeofday(&s1, NULL);

	pmap = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | flags, fd, 0);
	if (MAP_FAILED == pmap) {
		printf("[%3d][%6d:%6d] mmap failed. %s\n",
				cpu, getpid(), gettid(), strerror(errno));
		exit(1);
	}

	gettimeofday(&s2, NULL);

	if (g_act & ACT_WRITE) {
		act = "write";
		memset(pmap, 0xcc, MAP_SIZE);
	}
	else if (g_act & ACT_READ) {
		act = "read";
		for (i = 0; i < MAP_SIZE; ) {
			unsigned long ret = *(unsigned long *)(pmap + i);
			i += sizeof(unsigned long);
		}
	}
	else if (g_act & ACT_MLOCK) {
		act = "mlock";
		if (mlock(pmap, MAP_SIZE))
			printf("[%3d][%6d:%6d] mlock failed. %s\n",
					cpu, getpid(), gettid(), strerror(errno));
    }

	gettimeofday(&s3, NULL);
	
	if (g_act & ACT_MEMSET)
		memset(pmap, 0xcc, MAP_SIZE);
	
	gettimeofday(&s4, NULL);

	mmap_cost = time_diff(&s1, &s2);
	act_cost = time_diff(&s2, &s3);
	memset_cost = time_diff(&s3, &s4);
	
	if (g_debug)
		printf(/* [%03d][%6d:%6d][%ld.%ld] */"mmap %ld %s %ld memset %ld\n",
		/* cpu, getpid(), gettid(), s1.tv_sec, s1.tv_usec,*/
		mmap_cost, act, act_cost, memset_cost);

	pthread_mutex_lock(&stat_lock);

	mmap_cost_max = max(mmap_cost, mmap_cost_max);
	act_cost_max = max(act_cost, act_cost_max);
	memset_cost_max = max(memset_cost, memset_cost_max);

	mmap_cost_total += mmap_cost;
	act_cost_total += act_cost;
	memset_cost_total += memset_cost;
	show_stat++;

	pthread_mutex_unlock(&stat_lock);
}

static void *thread_fn(void *arg)
{
	int cpu = (int)arg;

	if (g_debug)
		printf("[%3d][%6d:%6d] enter\n", cpu, getpid(), gettid());

	set_new_name(cpu);
	bind_cpu(cpu);
	sleep(1);

	if ((cpu + 1) == g_cpu_num) {
		ready_go = 1;
		printf("\n\n");
	}

	while (!ready_go)
		asm volatile("rep; nop");

	do_mmap(cpu);

	return NULL;
}

static void create_threads(void)
{
	const int NUM_THREADS=4;
	int i, rc;
	int cpu_num;
	pthread_t t;

	if (g_cpu_num > 0)
		cpu_num = g_cpu_num;
	else {
		cpu_num = sysconf(_SC_NPROCESSORS_CONF);
		if (cpu_num <= 0)
			cpu_num = NUM_THREADS;
		g_cpu_num = cpu_num;
	}

	for (i = 0; i < cpu_num; i++) {
		if ((i + 1) == cpu_num)
			sleep(3);

		rc = pthread_create(&t, NULL, thread_fn, (void *)i);
		if (rc) {
			printf("[%3d] pthread_create failed. %s\n", i, strerror(errno));
			return;
		}
		
		if (g_debug)
			printf("[%3d] create success\n", i);
	}
}

void show_case(void)
{
	char *mmap_act = "MAP_SHARED";
	char *act = "no_act";
	char *memset_act = "no_memset";
	unsigned long avg_mmap;
	unsigned long avg_act;
	unsigned long avg_memset;

	if (g_act & ACT_POP)
		mmap_act = "MAP_POPULATE";

	if (g_act & ACT_WRITE)
		act = "write";
	else if ((g_act & ACT_READ))
		act = "read";
	else if ((g_act & ACT_MLOCK))
		act = "mlock";

	if (g_act & ACT_MEMSET)
		memset_act = "memset";
	
	avg_mmap = mmap_cost_total / g_cpu_num;
	avg_act = act_cost_total / g_cpu_num;
	avg_memset = memset_cost_total / g_cpu_num;
	
	printf("act(%02x) %12s %6s %9s total\n", g_act, mmap_act, act, memset_act);
	printf("max(ms) %12ld %6ld %9ld\n",
			mmap_cost_max, act_cost_max, memset_cost_max);
	printf("avg(ms) %12ld %6ld %9ld %5ld\n",
			avg_mmap, avg_act, avg_memset,
			(avg_mmap + avg_act + avg_memset));
}

int main(int argc, char *argv[])
{
	if (argc >= 2)
		g_act = atoi(argv[1]);
	if (argc >= 3)
		g_cpu_num = atoi(argv[2]);
	if (argc >= 4)
		g_debug = atoi(argv[3]);

	create_threads();
	printf("pid: %d, act: %x, cpu: %d, map size: %lu\n", getpid(), g_act, g_cpu_num, MAP_SIZE);

	while (show_stat != g_cpu_num)
		sleep(1);

	fflush(NULL);

	show_case();

	while (1)
		sleep(1);

	return 0;
}
