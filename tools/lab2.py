#!/usr/bin/python
from bcc import BPF
from bcc.utils import printb
from time import sleep

interval = 99999999

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};
struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 stack_id;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    u64 start_ts;
    //u64 seq;
};

//BPF_HASH(counts, struct key_t, u64, 256);
BPF_HASH(timestamp, u64, struct data_t);
BPF_PERF_OUTPUT(events);
//BPF_STACK_TRACE(stack_traces, 1024);    // 1024:STACK_STORAGE_SIZE
//BPF_HASH(counts, int, u64);
//int zero = 0;

int trace_pid_start(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
    
    u64 ts = bpf_ktime_get_ns();
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.stack_id = PT_REGS_IP(ctx);
    data.start_ts = ts;
    //u64* seq = counts.lookup(&zero);
    //data.seq = *seq;
    timestamp.update(&data.stack_id, &data);  
    //counts.increment(zero);

    return 0;
}

"""


# int trace_req_completion(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
#     struct data_t data = {};
#     struct task_struct *task;

#     data.pid = bpf_get_current_pid_tgid() >> 32;

#     struct data_t *org_data;
#     //u64 ts;

#     // fetch timestamp and calculate delta
#     org_data = timestamp.lookup(&address);
    
#     if (org_data == 0) {
#         // missed tracing issue
#         return 0;
#     }
#     u64 ts = bpf_ktime_get_ns();
#     //data.delta = ts - *tsp;
#     data.start_ts = org_data->start_ts;
#     //data.end_ts = ts;
#     //(*org_data).end_ts = ts;
#     //task = (struct task_struct *)bpf_get_current_task();

#     bpf_get_current_comm(data.comm, sizeof(data.comm));
#     //data.type = EVENT_RET;
#     //timestamp.delete(&address);
#     timestamp.update(&address, &data);
#     //events.perf_submit(ctx, &data, sizeof(data));

#     return 0;
# }
b = BPF(text=bpf_text)
b.attach_kprobe(event="down_read_trylock", fn_name="trace_pid_start")
b.attach_kprobe(event="_cond_resched", fn_name="trace_pid_start")
b.attach_kprobe(event="rcu_all_qs", fn_name="trace_pid_start")
b.attach_kprobe(event="find_vma", fn_name="trace_pid_start")
b.attach_kprobe(event="handle_mm_fault", fn_name="trace_pid_start")
b.attach_kprobe(event="__count_memcg_events", fn_name="trace_pid_start")
b.attach_kprobe(event="__handle_mm_fault", fn_name="trace_pid_start")

b.attach_kprobe(event="__handle_mm_fault", fn_name="trace_pid_start")
b.attach_kprobe(event="pmd_devmap_trans_unstable", fn_name="trace_pid_start")
b.attach_kprobe(event="filemap_map_pages", fn_name="trace_pid_start")
b.attach_kprobe(event="alloc_set_pte", fn_name="trace_pid_start")
b.attach_kprobe(event="pmd_devmap_trans_unstable", fn_name="trace_pid_start")
b.attach_kprobe(event="_raw_spin_lock", fn_name="trace_pid_start")
b.attach_kprobe(event="page_add_file_rmap", fn_name="trace_pid_start")
b.attach_kprobe(event="lock_page_memcg", fn_name="trace_pid_start")
b.attach_kprobe(event="unlock_page_memcg", fn_name="trace_pid_start")
b.attach_kprobe(event="__unlock_page_memcg", fn_name="trace_pid_start")

print('Tracing... Hit Ctrl-C to end.')

# output
try:
    sleep(interval)
except KeyboardInterrupt:
    pass

print(" %-6s %-25s %20s" % ("PID", "Funtion name", "start"))
ts = b.get_table("timestamp")
# stack_traces = b.get_table("stack_traces")

for k, v in sorted(ts.items(), key=lambda ts: ts[1].start_ts):
    printb(b"%-6d %-25s %20d" % (v.pid, b.ksym(v.stack_id), v.start_ts))
