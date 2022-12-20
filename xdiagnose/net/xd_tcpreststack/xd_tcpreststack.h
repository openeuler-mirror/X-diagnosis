#ifndef __XSTACK_H__
#define __XSTACK_H__

#define XDIAG_KERN_STACK_DEPTH 64

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN           16
#endif

struct event_tcpreststack {
    pid_t pid;
    char comm[TASK_COMM_LEN];
    unsigned int kstack_id;
    unsigned int saddr[4];
    unsigned int daddr[4];
    unsigned short sport;
    unsigned short dport;
    unsigned short protocol;
    unsigned short family;
};

#endif
