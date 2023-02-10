#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>


/* default run in cpu1 */
cpu_set_t cpuset;

pid_t gettid()
{
	return syscall(SYS_gettid);
}

void run_ms(unsigned int ms)
{
	int i, j;
	for(i = 0; i < ms; i++){
		j = 0;
		while(j < 300000)
			j++;
	}
}

void *rt_pthread_fn(void *arg)
{
	int ret;
	struct sched_param param;

	prctl(PR_SET_NAME, "test_rt_thread");
	param.sched_priority = 55;
	ret = sched_setscheduler(gettid(), SCHED_RR, &param);
	if(ret < 0){
		perror("rt_pthread_fn: sched_setscheduler failed");
		return NULL;
	}

	sched_setaffinity(gettid(), sizeof(cpu_set_t), &cpuset);

	while(1){
		run_ms(1000);
		sleep (2);
	}
	return NULL;
}

void *running_pthread_fn(void *arg)
{
	int ret;
	int runtime;
	prctl(PR_SET_NAME, "test_running_thread");
	sched_setaffinity(gettid(), sizeof(cpu_set_t), &cpuset);
	while(1){
		struct timeval tv;
		unsigned long long sstart, ustart, uwait;
		gettimeofday(&tv, NULL);
		ustart = tv.tv_usec;
		sstart = tv.tv_sec;
		runtime = 10;
		run_ms(runtime);
		gettimeofday(&tv, NULL);
		uwait = (tv.tv_sec - sstart) * 1000*1000 + tv.tv_usec - ustart - runtime;
		if(uwait > 100 * 1000)
			printf("EVENT: test_running_thread wait over %lldms\n", uwait / 1000);
	}
	return NULL;
}

void *wakeup_pthread_fn(void *arg)
{
	int ret;
	prctl(PR_SET_NAME, "test_wakeup_thread");
	sched_setaffinity(gettid(), sizeof(cpu_set_t), &cpuset);
	while(1){
		struct timeval tv;
		unsigned long long sstart, ustart, uwait;
		gettimeofday(&tv, NULL);
		ustart = tv.tv_usec;
		sstart = tv.tv_sec;
		usleep(1000);
		gettimeofday(&tv, NULL);
		uwait = (tv.tv_sec - sstart) * 1000*1000 + tv.tv_usec - ustart;
		if(uwait > 100 * 1000)
			printf("EVENT: test_wakeup_thread wait over %lldms\n", uwait / 1000);
	}
	return NULL;
}

void usage(char *cmd)
{
	printf("\tUSAGE: %s [cpuid]\n", cmd);
}

int main(int argc, char *argv[])
{
	int ret;
	int cpu;
	pthread_t rtid, runningtid, wakeuptid;

	if(argc < 2){
		usage(argv[0]);
		return 0;
	}
	cpu = atoi(argv[1]);
	/* set cpu affinaty */
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	ret = pthread_create(&rtid, NULL, rt_pthread_fn, NULL);
	if(ret < 0){
		printf("pthread_create failed: rt_pthread_fn");
		return 0;
	}

	ret = pthread_create(&runningtid, NULL, running_pthread_fn, NULL);
	if(ret < 0){
		printf("pthread_create failed: runing_pthread_fn");
		return 0;
	}

	ret = pthread_create(&wakeuptid, NULL, wakeup_pthread_fn, NULL);
	if(ret < 0){
		printf("pthread_create failed: wakeup_pthread_fn");
		return 0;
	}

	pthread_join(rtid, NULL);
	pthread_join(runningtid, NULL);
	pthread_join(wakeuptid, NULL);
	return 0;
}
