//#include <stdio.h>
//#include <stdlib.h>

#define MAX_SYMS 300000
#define MAX_KSTACK_DEPTH 127

#define MODULE_NAME_LEN 64
#define KSYM_NAME_LEN 128

struct ksym {
	long addr;
	char *name;
};

static struct ksym syms[MAX_SYMS];
static int sym_cnt;

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char buf[256];
	char func[KSYM_NAME_LEN+MODULE_NAME_LEN];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	while (!feof(f)) {
		if (!fgets(buf, sizeof(buf), f))
			break;
		if (sscanf(buf, "%p %c %[^\n]", &addr, &symbol, func) != 3)
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

void print_kern_stack(unsigned long *stack, int stack_depth)
{
	int i;
	struct ksym *sym;

	if(stack_depth > MAX_KSTACK_DEPTH)
		stack_depth = MAX_KSTACK_DEPTH;

	for(i = stack_depth - 1; i >= 0; i--){
		if(stack[i] == 0)
			continue;
		printf("%lx ", stack[i]);
		sym = ksym_search(stack[i]);
		printf("%s\n", sym->name);
	}
	printf("  ------ KERNEL STACK END ------ \n\n");
}

