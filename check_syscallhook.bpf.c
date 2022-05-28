#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "my_shared_defs.bpf.h"
#include "my_shared_defs.bpf.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";


#define MAX_KSYM_NAME_SIZE              64
#define MAX_KSYMADDR_MAP_ENTRIES        16

// #define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)
#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);                \
        _val;                                                           \
    })

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct {                                                    \
    __uint(type, BPF_MAP_TYPE_HASH);                        \
    __uint(max_entries, MAX_KSYMADDR_MAP_ENTRIES);          \
    __type(key, ksym_name_t);                               \
    __type(value, u64);                                     \
} ksymaddr_map SEC(".maps");

struct {                                                    \
    __uint(type, BPF_MAP_TYPE_HASH);                        \
    __uint(max_entries, NUMBER_OF_SYSCALLS_TO_CHECK_X86);   \
    __type(key, int);                                       \
    __type(value, u64);                                     \
} syscalls_to_check_map SEC(".maps");

static __always_inline void* get_symbol_addr(char *symbol_name)
{
    char new_ksym_name[MAX_KSYM_NAME_SIZE] = {};
    bpf_probe_read_str(new_ksym_name, MAX_KSYM_NAME_SIZE, symbol_name);
    // bpf_printk("new_ksym_name : %s\n",new_ksym_name);
    void **sym = bpf_map_lookup_elem(&ksymaddr_map, &new_ksym_name);

    if (sym == NULL)
    {
        bpf_printk("sym ==null\n");
        return 0;
    } 
    // bpf_printk("sym == ")
    return *sym;
}

static __always_inline void collect_event_uid(struct event *event)
{
        uint64_t id;


        id = bpf_get_current_uid_gid();
        event->uid = (uid_t)id;
        event->gid = id >> 32;
}
static __always_inline void collect_event_pid_info(struct event *event)
{
        uint64_t id;

        if (unlikely(!event))
                return;

        id = bpf_get_current_pid_tgid();
        event->tgid = id >> 32;
        event->pid = (pid_t)id;
}
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

int syscallhookflag[NUMBER_OF_SYSCALLS_TO_CHECK_X86];
const volatile bool debug = true;

// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
// {
// 	// unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
// 	struct event *e;
	
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	e->pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));
// 	// bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

// 	bpf_ringbuf_submit(e, 0);
// 	return 0;
// }
SEC("kretprobe/do_init_module")
int BPF_KRETPROBE(check_syscall_addr)
{
    
    // bpf_get_current_comm(&event->comm, sizeof(event->comm));
    // for(int i = 0;i<NUMBER_OF_SYSCALLS_TO_CHECK_X86;i++)
    // {
    //     event->syscallhookflag[i]=0;
    // }
    // bpf_probe_read_str(&event->filename, sizeof(event->filename), (void *)ctx + fname_off);

    

    bpf_printk("good1\n");
    int key = 0;
    char syscall_table[MAX_KSYM_NAME_SIZE] = "sys_call_table";
    char _stext[MAX_KSYM_NAME_SIZE] = "_stext";
    char _etext[MAX_KSYM_NAME_SIZE] = "_etext";
    u64 *table_ptr = bpf_map_lookup_elem(&syscalls_to_check_map, (void *)&key);
    if (table_ptr == NULL){
        bpf_printk("failed table_ptr\n");
        return -1;
    }

    u64 *syscall_table_addr = (u64*) get_symbol_addr(syscall_table);
    if (syscall_table_addr == 0)
    {
        bpf_printk("failed get syscall_table_addr\n");
        return -1;
    }
    u64 *_stext_addr = (u64*) get_symbol_addr(_stext);
    if (_stext_addr == 0)
    {
        bpf_printk("failed get _stext_addr\n");
        return -1;
    }
    u64 *_etext_addr = (u64*) get_symbol_addr(_etext);
    if (_etext_addr == 0)
    {
        bpf_printk("failed get _etext_addr\n");
        return -1;
    }
    u64 idx;
    u64* syscall_num_p;                  // pointer to syscall_number
    u64 syscall_num;
    u64 syscall_addr = 0;
    int monitored_syscalls_amount = 0;

    monitored_syscalls_amount = NUMBER_OF_SYSCALLS_TO_CHECK_X86;
    u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK_X86];

    bpf_printk("begin for\n");
    __builtin_memset(syscall_address, 0, sizeof(syscall_address));
    #pragma unroll
    for(int i =0; i < monitored_syscalls_amount; i++)
    {
        int index = syscallsToCheck[i];
        // idx = i;
        // int index = i;
        // syscall_num_p = bpf_map_lookup_elem(&syscalls_to_check_map, &index);
        // if (syscall_num_p == NULL){
        //     continue;
        // }
        // syscall_num = (u64)*syscall_num_p;
        // bpf_printk("syscall_num %d\n",syscall_num);
        // if(syscall_num==index)
        // {
        //     bpf_printk("idx and syscall_num is same!!!!!!!!!\n");
        // }
        // // bpf_printk("syscall_table_addr[syscall_num]  %lx\n",syscall_table_addr);

        // typeof(syscall_table_addr[syscall_num]) _val; 
        // // unsigned long _val;
        // __builtin_memset((void *)&_val, 0, sizeof(_val)); 
        // bpf_printk("syscall_num = %d\n",idx);
        // // bpf_printk("sizeof(u64) = %d\n",sizeof(unsigned long));
        // int ret = bpf_probe_read((void *)&_val, sizeof(_val), (const void*)&syscall_table_addr[syscall_num]); 
        // if (ret != 0)
        // {
        //     bpf_printk("core read failed ret = %d\n",ret);
        //     return -1;
        // }
        // syscall_addr = _val;

        syscall_addr = READ_KERN(syscall_table_addr[index]);
        if (syscall_addr == 0){
            bpf_printk("addr = 0 count%d\n",i);
            return -1;
        }
        syscall_address[i] = syscall_addr;
        if (syscall_address[i]>(u64)_etext_addr||syscall_address[i]<(u64)_stext_addr)
        {
            syscallhookflag[i] = 1;
            if (debug)
            {
                bpf_printk("hooked!!!!!!!!!\nsyscall num:%d   syscall addr %lx\n",index,syscall_address[i]);
            }
        }
        else
        {
            syscallhookflag[i] = 0;
            if (debug)
            {
                bpf_printk("safety\nsyscall num:%d  syscall ptr%lx syscall addr %lx\n",index,&syscall_address[i],syscall_address[i]);
            }
        }
    }
    bpf_printk("good\n");
    // // 提交事件
    // bpf_ringbuf_submit(event, 0);
    struct event * event;
    bpf_printk("sizeof event %d\n",sizeof(struct event*));
    event = bpf_ringbuf_reserve(&rb,sizeof(*event),0);
    if (!event)
    {
        bpf_printk("event error");
        return 0;
    }
    event->eventname=0;
    collect_event_pid_info(event);
    collect_event_uid(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    for(int i = 0;i<NUMBER_OF_SYSCALLS_TO_CHECK_X86;i++)
    {
        event->syscallhookflag[i]=syscallhookflag[i];
    }
    bpf_ringbuf_submit(event, 0);
}


SEC("lsm/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file, int ret)
{
        bpf_printk("in fileless\n");
        uint32_t *val, blocked = 0, reason = 0, zero = 0;
        unsigned int links;
        struct task_struct *task;
        struct file *f;
        const unsigned char *p;

        if (ret != 0 )
                return ret;

        links = BPF_CORE_READ(file, f_path.dentry, d_inode, __i_nlink);
        if (links > 0)
                return ret;
                
        struct event * event;
        bpf_printk("sizeof event %d\n",sizeof(struct event*));
        event = bpf_ringbuf_reserve(&rb,sizeof(*event),0);
        if (!event)
        {
                bpf_printk("event error");
                return 0;
        }
        p = BPF_CORE_READ(file, f_path.dentry, d_name.name);
        bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), p);
        event->eventname=1;
        collect_event_pid_info(event);
        collect_event_uid(event);
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        bpf_ringbuf_submit(event, 0); 
        return -1;
}



SEC("lsm/kernel_module_request")
int BPF_PROG(km_autoload, char *kmod_name, int ret)
{
    if (ret != 0)
        return ret;
    struct event * event;
    bpf_printk("sizeof event %d\n",sizeof(struct event*));
    event = bpf_ringbuf_reserve(&rb,sizeof(*event),0);
    if (!event)
    {
            bpf_printk("event error");
            return 0;
    }
    bpf_probe_read_kernel_str(&event->filename,sizeof(event->filename), kmod_name); 
    event->eventname=2;
    collect_event_pid_info(event);
    collect_event_uid(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return -1;
}



SEC("lsm/kernel_read_file")
int BPF_PROG(km_read_file, struct file *file,
             enum kernel_read_file_id id, bool contents, int ret)
{
    if (ret != 0)
            return ret;
    const char *p;
    struct event * event;
    bpf_printk("sizeof event %d\n",sizeof(struct event*));
    event = bpf_ringbuf_reserve(&rb,sizeof(*event),0);
    if (!event)
    {
            bpf_printk("event error");
            return 0;
    }
    p = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), p);
    event->eventname=2;
    collect_event_pid_info(event);
    collect_event_uid(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return -1;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    const int sudoers_len = 13;
    const char *sudoers = "/etc/sudoers";
    char filename[sudoers_len];
    bpf_probe_read_user(&filename, sudoers_len, (char*)ctx->args[1]);
    for (int i = 0; i < sudoers_len; i++) {
        if (filename[i] != sudoers[i]) {
            return 0;
        }
    }
    struct event * event;
    bpf_printk("sizeof event %d\n",sizeof(struct event*));
    event = bpf_ringbuf_reserve(&rb,sizeof(*event),0);
    if (!event)
    {
            bpf_printk("event error");
            return 0;
    }
    event->eventname=3;
    collect_event_pid_info(event);
    collect_event_uid(event);
     bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), filename);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
}
