#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";


#define MAX_KSYM_NAME_SIZE              64
#define MAX_KSYMADDR_MAP_ENTRIES        16
#define NUMBER_OF_SYSCALLS_TO_CHECK_X86 18
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

struct {                                                    \
    __uint(type, BPF_MAP_TYPE_HASH);                        \
    __uint(max_entries, MAX_KSYMADDR_MAP_ENTRIES);          \
    __type(key, ksym_name_t);                               \
    __type(value, u64);                                     \
} ksymaddr_map SEC(".maps");

struct {                                                    \
    __uint(type, BPF_MAP_TYPE_HASH);                        \
    __uint(max_entries, NUMBER_OF_SYSCALLS_TO_CHECK_X86);          \
    __type(key, int);                               \
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
SEC("kretprobe/do_init_module")
int BPF_KRETPROBE(check_syscall_addr)
{
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
            bpf_printk("hooked!!!!!!!!!\nsyscall num:%d   syscall addr %lx\n",index,syscall_address[i]);
        }
        else
        {
            bpf_printk("safety\nsyscall num:%d  syscall ptr%lx syscall addr %lx\n",index,&syscall_address[i],syscall_address[i]);
        }
    }
    bpf_printk("good\n");
}