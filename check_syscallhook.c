#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "my_shared_defs.bpf.h"
// #include <bpf/bpf_helpers.h>
#include <bpf/bpf.h>
#include "check_syscallhook.skel.h"
// #include ".output/check_syscallhook.skel.h"
// #include "get_symbol_addr_utils.h"


// #include <stdio.h>
#include <stdint.h>
#include <string.h>
#define SYMBOL_NUMS 10
#define LINE_MAX 256
#define TYPE_MAX 1
#define MAX_KSYM_NAME_SIZE 64
#define OWNER_MAX 50

#define NUMBER_OF_SYSCALLS_TO_CHECK_X86 18


const volatile bool debug = false;


typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

char syscallname[20][NUMBER_OF_SYSCALLS_TO_CHECK_X86]={
	"read",
	"write",
	"open",
	"close",
	"ioctl",
	"socket",
	"sendto",
	"recvfrom",
	"sendmsg",
	"recvmsg",
	"execve",
	"kill",
	"getdents",
	"ptrace",
	"getdents64",
	"openat",
	"bpf",
	"execveat"
};
int syscallsToCheck[]={
	0,   // read
	1,   // write
	2,   // open
	3,   // close
	16,  // ioctl
	41,  // socket
	44,  // sendto
	45,  // recvfrom
	46,  // sendmsg
	47,  // recvmsg
	59,  // execve
	62,  // kill
	78,  // getdents
	101, // ptrace
	217, // getdents64
	257, // openat
	321, // bpf
	322, // execveat
};


int get_symbol_addr(uint64_t *Address,char name[][MAX_KSYM_NAME_SIZE])
{
    FILE* fp;
    // uint64_t Address[SYMBOL_NUMS];
    char type[SYMBOL_NUMS];
    // char name[SYMBOL_NUMS][NAME_MAX];
    char owner[SYMBOL_NUMS][OWNER_MAX];
    // char type1;
    char line[LINE_MAX];
    int line_index = 0;
    char sys_call_table[15]="sys_call_table";
    char _etext_name[7]="_etext";
    char _stext_name[7]="_stext";

    fp = fopen("/proc/kallsyms","r'");
    if(fp == NULL)
    {
        printf("err open file failed");
        return -1;
    }
    while (!feof(fp))
    {
        fgets(line,LINE_MAX,fp);
        // printf("%s",line);

        int ret = sscanf(line,"%16lx %c %s [%s]",&Address[line_index],&type[line_index],name[line_index],owner[line_index]);
        //比较该行符号是否为要寻找的符号
        if (strcmp(name[line_index],sys_call_table)&&strcmp(name[line_index],_etext_name)&&strcmp(name[line_index],_stext_name))
        {
            continue;
        }
        // 找到符号地址，打印
        printf("ret = %d\nAddress=%lx\ntype=%c\nname=%s\n",ret,Address[line_index],type[line_index],name[line_index]);
        line_index++;
    }
    return 0;
}



static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}
void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}
int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->comm, e->filename);
	switch (e->eventname)
	{
	case 0:
		printf("%-8s %-20s %-7d %-7d %-7d %-7d %-16s\n", ts, "Syscall hijacking", e->pid,e->tgid,e->uid,e->gid, e->comm);
		printf("Details:\n");
		for (int i = 0; i < NUMBER_OF_SYSCALLS_TO_CHECK_X86; i++)
		{
			if (e->syscallhookflag[i]==1)
			{
			printf("syscall %d %s is hooked\n",syscallsToCheck[i],syscallname[i]);
			}
		// else
		// {
		// 	printf("syscall %d  is safe\n",syscallsToCheck[i]);
		// }
		}
		return 0;
		break;
	case 1:
		printf("%-8s %-20s %-7d %-7d %-7d %-7d %-16s\n", ts, "Fileless attack", e->pid,e->tgid,e->uid,e->gid, e->comm);
		printf("Details:\n");
		printf("filename: %s\n",e->filename);
		break;
	case 2:
		printf("%-8s %-20s %-7d %-7d %-7d %-7d %-16s\n", ts, "Kmod invalid load", e->pid,e->tgid,e->uid,e->gid, e->comm);
		printf("Details:\n");
		printf("kmod name: %s\n",e->filename);
		break;
	default:
		break;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct check_syscallhook_bpf *skel;
	int err;
	int addr_fd,check_fd;
	uint64_t Address[SYMBOL_NUMS];
	char name[SYMBOL_NUMS][MAX_KSYM_NAME_SIZE];
	ksym_name_t name_key;
	ksym_name_t name_key_test;


	bump_memlock_rlimit();
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	if(get_symbol_addr(Address,name))
		return -1;
	
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = check_syscallhook_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	printf("1\n");

	


	/* ensure BPF program only handles write() syscalls from our process */
	// skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = check_syscallhook_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}


	// 初始化map
	addr_fd = bpf_map__fd(skel->maps.ksymaddr_map);
	check_fd = bpf_map__fd(skel->maps.syscalls_to_check_map);
	for (int tmp = 0; tmp < 3; tmp++)
	{
		if (debug)
			printf("name: %s addr: %lx\n",name[tmp],Address[tmp]);
		strcpy(name_key.str,name[tmp]);
		// printf("namekey:%s\n",name_key.str);
		int ret=bpf_map_update_elem(addr_fd,&name_key,&Address[tmp],BPF_ANY);
		if (ret == -1) 
		{
        printf("Failed to addr_fd\n");
        goto cleanup;
		}			
	}
	if (debug)
	{

		ksym_name_t recheckname[3];
		uint64_t recheck[3];
		for (int tmp = 0; tmp < 3; tmp++)
		{
			strcpy(recheckname[tmp].str,name[tmp]);
			int ret =bpf_map_lookup_elem(addr_fd,&recheckname[tmp], &recheck[tmp]);
			if (ret == -1) 
			{
				printf("Failed to recheck\n");
			}
			else
			{
				printf("index %d is addr %lx\n",tmp,recheck[tmp]);
			}
		}
	}
	// uint64_t addr_test;
	// char keyname[MAX_KSYM_NAME_SIZE]="sys_call_table";
	// printf("name_key.str%s\n",name_key.str);
	// int ret = strcmp(keyname,name[2]);
	// if(ret ==0)
	// {
	// 	printf("same!!!!\n");
	// }
	// else
	// {
	// 	printf("not same!!\n");
	// }
	
	// strcpy(name_key_test.str,name[2]);
	// int ret = bpf_map_lookup_elem(addr_fd,keyname,&addr_test);
	// if(ret !=0)
	// {
	// 	printf("ret = %d",ret);
	// 	return -1;
	// }
	// printf("ret %d\n",ret);
	// printf("addr_test = %lx\n",addr_test);

	for (int tmp = 0; tmp < NUMBER_OF_SYSCALLS_TO_CHECK_X86; tmp++)
	{
		int ret=bpf_map_update_elem(check_fd,(void *)&tmp,&syscallsToCheck[tmp],BPF_ANY);
		if (ret == -1) 
		{
        printf("Failed to check_fd\n");
        goto cleanup;
		}
	}
	// int syscallsrecheck[NUMBER_OF_SYSCALLS_TO_CHECK_X86];
	// for (int tmp = 0; tmp < NUMBER_OF_SYSCALLS_TO_CHECK_X86; tmp++)
	// {
	// 	int ret=bpf_map_lookup_elem(check_fd,(void *)&tmp,&syscallsrecheck[tmp]);
	// 	if (ret == -1) 
	// 	{
    //     printf("Failed to recheck\n");
	// 	}
	// 	else
	// 	{
	// 		printf("index %d is num %d\n",tmp,syscallsrecheck[tmp]);
	// 	}
	// }


	/* Attach tracepoint handler */
	err = check_syscallhook_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	printf("%-8s %-20s %-7s %-7s %-7s %-7s %-16s\n",
	       "TIME", "EVENT", "PID","TGID","UID","GID","COMM");
	while (!exiting) 
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}	
	// for (;;) {
	// 	/* trigger our BPF program */
	// 	fprintf(stderr, ".");
	// 	sleep(1);
	// }

cleanup:
	ring_buffer__free(rb);
	check_syscallhook_bpf__destroy(skel);
	return -err;
}