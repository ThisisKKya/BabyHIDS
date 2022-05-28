#include "compiler.h"
// #include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN           20

#define NUMBER_OF_SYSCALLS_TO_CHECK_X86 18
#define MAX_FILENAME_LEN 512
#ifndef NAME_MAX
#define NAME_MAX                255
#define PATH_MAX                4096
#endif

#define TASK_FILENAME_LEN       64
#define DATA_LEN                64

#ifndef INVALID_UID
#define INVALID_UID             ((uid_t)-1)
#endif




struct event {
	int pid;
	char comm[TASK_COMM_LEN];
	// char filename[MAX_FILENAME_LEN];
	int syscallhookflag[NUMBER_OF_SYSCALLS_TO_CHECK_X86];
};

/* #pragma pack(4) */
// struct process_event {
//         int             prog_type;
//         int             attach_type;

//         int             program_id;
//         int             event_id;
//         int             operation_id;

//         pid_t           tgid;
//         // pid_t           pid;
//         int           pid;
//         pid_t           ppid;
//         uid_t           uid;
//         gid_t           gid;
//         unsigned int    sessionid;
//         int             reserved1;

//         // uint64_t        cgroup_id;
//         // uint64_t        parent_cgroup_id;

//         // unsigned int    mntns_id;
//         // unsigned int    pidns_id;
//         // uint64_t        netns_id;

//         /* Return value of the bpf program for LSM or of the kernel function */
//         int             retval;

//         /* Map filters that matched the access */
//         int             matched_filter;

//         /* Reason why access was allowed : enum reason_value */
//         int             reason;

//         int             reserved2;

//         char            comm[TASK_COMM_LEN];
//         char            pcomm[TASK_COMM_LEN];
//         /* TODO: use full path length and store in map the whole struct */
//         char            filename[TASK_FILENAME_LEN];
//         char            data[DATA_LEN];
// };

// static __always_inline void collect_event_types(struct process_event *event, int ptype,
//                                                 int attach, int progid, int eventid)
// {
//         if (unlikely(!event))
//                 return;

//         event->prog_type = ptype;
//         event->attach_type = attach;
//         event->program_id = progid;
//         event->event_id = eventid;
// }

// static __always_inline void collect_event_uid(struct process_event *event)
// {
//         uint64_t id;

//         if (unlikely(!event))
//                 return;

//         id = bpf_get_current_uid_gid();
//         event->uid = (uid_t)id;
//         event->gid = id >> 32;
// }

// static __always_inline void collect_event_pid_info(struct process_event *event)
// {
//         struct task_struct *task;
//         uint64_t id;

//         if (unlikely(!event))
//                 return;

//         id = bpf_get_current_pid_tgid();
//         event->tgid = id >> 32;
//         event->pid = (pid_t)id;

//         // task = (struct task_struct*)bpf_get_current_task();
//         // event->cgroup_id = bpf_get_current_cgroup_id();
//         // event->pidns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
//         // event->mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
//         // event->netns_id = BPF_CORE_READ(task, nsproxy, net_ns, net_cookie);
// }

// static __always_inline void collect_event_pid_comm(struct process_event *event, bool parent)
// {
//         const char unsigned *p;
//         struct task_struct *task;

//         if (unlikely(!event))
//                 return;

//         bpf_get_current_comm(&event->comm, sizeof(event->comm));

//         /* racy... */
//         if (parent && event->tgid > 1) {
//                 task = (struct task_struct*)bpf_get_current_task();
//                 event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, pid);
//                 p = (char unsigned *)BPF_CORE_READ(task, real_parent, comm);
//                 bpf_probe_read_kernel_str(&event->pcomm, sizeof(event->pcomm), p);
//         }
// }



// static __always_inline void collect_event_info(struct process_event *event, int ptype,
//                                                 int attach, int progid, int eventid)
// {
//         collect_event_types(event, ptype, attach, progid, eventid);
//         collect_event_uid(event);
//         collect_event_pid_info(event);
//         collect_event_pid_comm(event, true);
// }