#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <asm/types.h>
#include <stdarg.h>
#include <sys/resource.h>


/* for bpf*/
#include <linux/bpf.h>
#include <bpf/bpf.h>
/*  bpf end */

#include "xd_tcpreststack.h"
#include "common_u.h"
#include "xd_tcpreststack.skel.h"

#define MAX_SYMS 300000

struct ksym {
        long addr;
        char *name;
};

static struct ksym syms[MAX_SYMS];
static int sym_cnt;
static int stack_mapfd;
static int stack_infofd;
/* For Input Parameter */
/* depth of kernel stack, default 3 */
static int stack_depth = 3;
/* interval time of detection, default 200 */
static int interval_time = 200;

static const struct option long_opts[] = {
    { "help", 0, 0, 'h' },
    { "time", 1, 0, 't' },
    { "depth", 1, 0, 'd' },
    { 0 }
};

static int ksym_cmp(const void *p1, const void *p2)
{
        return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

static int load_kallsyms(void)
{
        FILE *f = fopen("/proc/kallsyms", "r");
        char func[256], buf[256];
        char symbol;
        void *addr;
        int i = 0;

        if (!f)
                return -ENOENT;

        while (!feof(f)) {
                if (!fgets(buf, sizeof(buf), f))
                        break;
                if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
                        break;
                if (!addr)
                        continue;
                syms[i].addr = (long) addr;
                syms[i].name = strdup(func);
                i++;
        }
        fclose(f);
        sym_cnt = i;
        qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
        return 0;
}

static struct ksym *ksym_search(long key)
{
        int start = 0, end = sym_cnt;

        /* kallsyms not loaded. return NULL */
        if (sym_cnt <= 0)
                return NULL;

        while (start < end) {
                size_t mid = start + (end - start) / 2;

                if ((int)key < (int)(syms[mid].addr))
                        end = mid;
                else if ((int)key > (int)(syms[mid].addr))
                        start = mid + 1;
                else
                        return &syms[mid];
        }
        
        if (start >= 1 && syms[start - 1].addr < key &&
            key < syms[start].addr)
                /* valid ksym */
                return &syms[start - 1];

        /* out of range. return _stext */
        return &syms[0];
}

static void usage(char *cmd)
{
    printf("Usage: xd_tcpreststack [ OPTIONS ]\n"
            "   -h,--help           this message\n"
            "   -t,--time           The frequency of the probe/ms\n"
            "   -d,--depth           Kernel stack Depth\n");
}

static void print_kern_stack(unsigned long *stack)
{
    int i;
    struct ksym *sym;

    for(i = stack_depth - 1; i >= 0; i--){
        if(stack[i] == 0)
            continue;
        printf("%lx ", stack[i]);
        sym = ksym_search(stack[i]);
        printf("%s\n", sym->name);
    }
    printf("  ------ KERNEL STACK END ------ \n\n");
}

static void print_info(struct key_xd_tcpreststack *key)
{
    char src_ip[64];
    char dst_ip[64];
    memset(src_ip, 0, sizeof(src_ip));
    memset(dst_ip, 0, sizeof(dst_ip));
    inet_ntop(key->family, key->saddr, src_ip, sizeof(src_ip));
    inet_ntop(key->family, key->daddr, dst_ip, sizeof(dst_ip));
    printf(" ============== pid: %d, comm:%s ============\n",
            key->pid, key->comm);
    printf(" -- %s:%u    %s:%u --\n", 
            src_ip, ntohs(key->sport),
            dst_ip, ntohs(key->dport));
}

static int print_xd_tcpreststacks(void)
{
    int ret;
    int running = 1;
    unsigned int kstack_id = 0;
    unsigned int next_id = 0;
    struct key_xd_tcpreststack key, next_key;
    unsigned long stack[XDIAG_KERN_STACK_DEPTH];
    
    if (load_kallsyms()) {
        printf("failed to process /proc/kallsyms\n");
        return -1;
    }

    while(running){
        memset(&key, 0x0, sizeof(struct key_xd_tcpreststack));
        memset(&next_key, 0x0, sizeof(struct key_xd_tcpreststack));
        memset(stack, 0x0, sizeof(stack));
        while(bpf_map_get_next_key(stack_infofd, &key, &next_key) == 0){
            kstack_id = next_key.kstack_id;
            ret = bpf_map_lookup_elem(stack_mapfd, &kstack_id, &stack);
            if(ret != 0){
                printf("stack_mapfd: bpf_map_lookup_elem failed\n");
                continue;
            }
            print_info(&next_key);
            print_kern_stack(stack);
            bpf_map_delete_elem(stack_infofd, &next_key);
            key = next_key;
        }

        kstack_id = 0;
        while (bpf_map_get_next_key(stack_mapfd, &kstack_id, &next_id) == 0){
            bpf_map_delete_elem(stack_mapfd, &next_id);
            kstack_id = next_id;
        }
        usleep(interval_time * 1000);
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
    int ch;
    struct xd_tcpreststack_bpf *skel;

    while ((ch = getopt_long(argc, argv, "hd:t:", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'd':
            stack_depth = atoi(optarg);
            break;
        case 't':
            interval_time = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            return ret;
        default:
            printf("invalid argument\n");
            return -1;
        }
    }

    memlock_rlimit();

    skel = xd_tcpreststack_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }   

    /* Attach tracepoint */
    ret = xd_tcpreststack_bpf__attach(skel);
    if (ret) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        ret =  -1;
        goto cleanup;
    }

    stack_mapfd = bpf_map__fd(skel->maps.stack_map);
    if (stack_mapfd < 0) {
        fprintf(stderr, "Failed to get BPF map fd\n");
        ret =  -1;
        goto cleanup;
    }

    stack_infofd = bpf_map__fd(skel->maps.stackinfo_map);
    if (stack_infofd < 0) {
        fprintf(stderr, "Failed to get BPF map fd\n");
        ret =  -1;
        goto cleanup;
    }

    print_xd_tcpreststacks();

cleanup:
    xd_tcpreststack_bpf__destroy(skel);
    return ret;
}

