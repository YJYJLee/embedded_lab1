#!/usr/bin/python
from bcc import BPF
from bcc.utils import printb
from time import sleep
import argparse

interval = 99999999

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

//enum event_type {
//    EVENT_ARG,
//    EVENT_RET,
//};
struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 stack_id;
    char comm[TASK_COMM_LEN];
    //enum event_type type;
    u64 start_ts;
    //u64 seq;
};
struct key_t_1{
    u64 stack_id;
    unsigned long addr;
};
struct key_t_2{
    u64 stack_id;
    unsigned long addr;
    unsigned int flags;
    unsigned long vma_addr;
    unsigned long vm_start;
    unsigned long vm_end;
};
struct key_t_3{
    u64 stack_id;
    //unsigned long addr;
    unsigned long vma_addr;
};

//BPF_HASH(counts, struct key_t, u64, 256);
//BPF_HASH(timestamp1, struct key_t_1, struct data_t);
BPF_HASH(timestamp1, struct key_t_2, struct data_t);
BPF_HASH(timestamp2, struct key_t_2, struct data_t);
BPF_HASH(timestamp3, struct key_t_2, struct data_t);
BPF_HASH(timestamp4, struct address_space *, struct data_t);
BPF_HASH(timestamp1_count, struct key_t_2, u64);
BPF_HASH(timestamp2_count, struct key_t_2, u64);
BPF_HASH(timestamp3_count, struct key_t_2, u64);
//BPF_PERF_OUTPUT(events);
//BPF_STACK_TRACE(stack_traces, 1024);    // 1024:STACK_STORAGE_SIZE
//BPF_HASH(counts, int, u64);
//int zero = 0;
BPF_HASH(counts, struct key_t_2, u64, 256);


int kprobe_handle_mm_fault(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
    u64 ts = bpf_ktime_get_ns();
    struct data_t data = {};
    struct key_t_2 key = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.stack_id = PT_REGS_IP(ctx);
    data.start_ts = ts;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    key.stack_id = data.stack_id;
    key.vma_addr = (unsigned long)(vma);
    key.vm_start = vma->vm_start;
    key.vm_end = vma->vm_end;
    key.addr = address;
    key.flags = flags;
    timestamp1_count.increment(key);
    struct data_t* p = timestamp1.lookup(&key);
    if (p != 0) {
        // missed tracing issue
        return 0;
    }
    timestamp1.update(&key, &data);
    counts.increment(key); 
    return 0;
}

int kprobe_filemap_map_pages(struct pt_regs *ctx, struct vm_fault *vmf, pgoff_t start_pgoff, pgoff_t end_pgoff) {
    u64 ts = bpf_ktime_get_ns();
    struct data_t data = {};
    struct key_t_2 key = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.stack_id = PT_REGS_IP(ctx);
    data.start_ts = ts;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    //key.addr = ctx->ax;
    key.stack_id = data.stack_id;
    key.vma_addr = (unsigned long)(vmf->vma);
    key.vm_start = vmf->vma->vm_start;
    key.vm_end = vmf->vma->vm_end;
    timestamp2_count.increment(key);

    struct data_t* p = timestamp2.lookup(&key);
    if (p != 0) {
        // missed tracing issue
        return 0;
    }
    timestamp2.update(&key, &data);

    return 0;
    }
int kprobe_ext4_filemap_fault(struct pt_regs *ctx,  struct vm_fault *vmf) {
    u64 ts = bpf_ktime_get_ns();
    struct data_t data = {};
    struct key_t_2 key = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.stack_id = PT_REGS_IP(ctx);
    data.start_ts = ts;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    key.stack_id = data.stack_id;
    key.vma_addr = (unsigned long)(vmf->vma);
    key.vm_start = vmf->vma->vm_start;
    key.vm_end = vmf->vma->vm_end;
    struct data_t* p = timestamp3.lookup(&key);
    if (p != 0) {
        // missed tracing issue
        return 0;
    }
    timestamp3_count.increment(key);

    timestamp3.update(&key, &data);
 
    return 0;
}
int kprobe_pagecache_get_page(struct pt_regs *ctx, struct address_space *mapping, pgoff_t offset, int fgp_flags, gfp_t gfp_mask) {
    u64 ts = bpf_ktime_get_ns();
    struct data_t data = {};
    struct key_t_2 key = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.stack_id = PT_REGS_IP(ctx);
    data.start_ts = ts;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    //key.stack_id = data.stack_id;
    //key.vma_addr = (unsigned long)(vmf->vma);
    //key.vm_start = vmf->vma->vm_start;
    //key.vm_end = vmf->vma->vm_end;

    struct data_t* p = timestamp4.lookup(&mapping);
    if (p != 0) {
        // missed tracing issue
        return 0;
    }

    timestamp4.update(&mapping, &data);
         

    return 0;
}

"""
# int kprobe_do_page_fault(struct pt_regs *ctx) {
#     u64 ts = bpf_ktime_get_ns();
#     struct data_t data = {};
#     struct key_t_1 key = {};
#     data.pid = bpf_get_current_pid_tgid() >> 32;
#     data.stack_id = PT_REGS_IP(ctx);
#     data.start_ts = ts;
#     bpf_get_current_comm(&data.comm, sizeof(data.comm));
#     key.stack_id = data.stack_id;
#     //key.addr = addr;
#     timestamp1.update(&key, &data);
#     return 0;
# }
# int kprobe_alloc_pages_current(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_add_to_page_cache_lru(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_ext4_mpage_readpages(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_ext4_map_blocks(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_submit_bio(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_io_schedule(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_enter_lazy_tlb(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_irq_enter(struct pt_regs *ctx, ) {
#     return 0;
# }
# int kprobe_finish_task_switch(struct pt_regs *ctx, ) {
#     return 0;
# }



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
examples = """examples:
    ./lab2.py           
"""

parser = argparse.ArgumentParser(
    description="Lab2",
    formatter_class=argparse.RawDescriptionHelpFormatter, epilog=examples)
parser.add_argument("-p", "--pid", type=int, default=-1, metavar='PID',
    help="trace this PID only")

args = parser.parse_args()

b = BPF(text=bpf_text)
# b.attach_kprobe(event="do_page_fault", fn_name="kprobe_do_page_fault")
b.attach_kprobe(event="handle_mm_fault", fn_name="kprobe_handle_mm_fault")
b.attach_kprobe(event="filemap_map_pages", fn_name="kprobe_filemap_map_pages")
b.attach_kprobe(event="ext4_filemap_fault", fn_name="kprobe_ext4_filemap_fault")
b.attach_kprobe(event="pagecache_get_page", fn_name="kprobe_pagecache_get_page")
# b.attach_kprobe(event="alloc_pages_current", fn_name="trace_pid_start")
# b.attach_kprobe(event="add_to_page_cache_lru", fn_name="trace_pid_start")
# b.attach_kprobe(event="ext4_mpage_readpages", fn_name="trace_pid_start")
# b.attach_kprobe(event="ext4_map_blocks", fn_name="trace_pid_start")
# b.attach_kprobe(event="submit_bio", fn_name="trace_pid_start")
# b.attach_kprobe(event="io_schedule", fn_name="trace_pid_start")
# b.attach_kprobe(event="enter_lazy_tlb", fn_name="trace_pid_start")
# b.attach_kprobe(event="irq_enter", fn_name="trace_pid_start")
# b.attach_kprobe(event="finish_task_switch", fn_name="trace_pid_start")

print('Tracing... Hit Ctrl-C to end.')

# output
try:
    sleep(interval)
except KeyboardInterrupt:
    pass

# print(" %-6s %-20s %-20s %-25s %20s" % ("PID", "COMMAND", "ADDR", "Funtion name", "start"))
print(" %-6s %-20s %-25s %20s" % ("PID", "COMMAND", "Funtion name", "start"))
tss = []
for i in range(4):
    tss.append(b.get_table("timestamp"+str(i+1)))

count1 = b.get_table("timestamp1_count")
count2 = b.get_table("timestamp2_count")
count3 = b.get_table("timestamp3_count")


def check_condition(condition, prev_k, prev_v, sub_k, sub_v):
    if condition == "address":
        return sub_k.addr == prev_k.addr
    elif condition == "vma_address":
        return (sub_k.vma_addr == prev_k.vma_addr) and (sub_k.vm_start == prev_k.vm_start) and (sub_k.vm_end == prev_k.vm_end)
    # elif condition == "address_space":
    #     return (sub_k.vma)

def find_calls(condition, prev_k, prev_v, tables):
    if prev_k == -1 and prev_v == -1:
        return -1, -1
    found = False
    for sub_k, sub_v in tables:
        if check_condition(condition, prev_k, prev_v, sub_k, sub_v):
            printb(b"%-6d %-20s %-25s %20d" % (sub_v.pid, sub_v.comm, b.ksym(sub_v.stack_id), sub_v.start_ts))
            found = True
            return sub_k, sub_v
    # printb(b"%-6d %-20s %-20x %-25s Not found" % (prev_v.pid, prev_v.comm, prev_k.addr, b.ksym(tables[0][1].stack_id)))
    printb(b"Not found")
    return -1, -1

# f_calls_list = []
# for ts in tss:
#     f_calls = {}
#     for k, v in sorted(ts.items(), key=lambda ts: ts[1].pid):
#         if v.pid in f_calls:
#             if k.addr in f_calls[v.pid]:
#                 f_calls[v.pid][k.addr].append(v)
#             else:
#                 f_calls[v.pid][k.addr] = [v]
#         else:
#             f_calls[v.pid]={}
#             f_calls[v.pid][k.addr]=[v]
#     f_calls_list.append(f_calls)

# print("f_calls: ", len(f_calls_list))

isPrint = True
print(len(tss[0].items()))
for k, v in tss[0].items(): # f_calls of find_vma
    # if args.pid!=-1:
    #     if v.pid != args.pid:
    #         isPrint = False
    #         continue
    #     else:
    #         print(v.pid)
    #         isPrint = True
    # if isPrint:
    printb(b"%-6d %-20s %-25s %20d" % (v.pid, v.comm, b.ksym(v.stack_id), v.start_ts))
    print("count1 : ", count1[k])

    sub_k, sub_v = find_calls("vma_address", k, v, tss[1].items())
    if sub_k != -1:
        print("count2 : ", count2[sub_k])

    sub_k, sub_v = find_calls("vma_address", sub_k, sub_v, tss[2].items())
    if sub_k != -1:
        print("count3 : ", count3[sub_k])

    sub_k, sub_v = find_calls("address_space", sub_k, sub_v, tss[3].items())


    printb(b"HEHE")
