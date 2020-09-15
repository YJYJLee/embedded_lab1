#!/usr/bin/python
#
# oomkill   Trace oom_kill_process(). For Linux, uses BCC, eBPF.
#
# This traces the kernel out-of-memory killer, and prints basic details,
# including the system load averages. This can provide more context on the
# system state at the time of OOM: was it getting busier or steady, based
# on the load averages? This tool may also be useful to customize for
# investigations; for example, by adding other task_struct details at the time
# of OOM.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Feb-2016   Brendan Gregg   Created this.

from bcc import BPF
from time import strftime, sleep
from sys import argv

# # linux stats
# loadavg = "/proc/loadavg"

interval = 99999999
if len(argv) > 1:
    try:
        interval = int(argv[1])
        if interval == 0:
            raise
    except:  # also catches -h, --help
        pass

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

struct key_t {
    //u64 ip;
    char filename[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t, u64, 256);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    //key.ip = PT_REGS_IP(ctx);
    bpf_get_current_comm(&key.filename, sizeof(key.filename));
    //u64 *tsp = counts.lookup(&key);

    counts.increment(key);
    return 0;
}

"""

# # process event
# def print_event(cpu, data, size):
#     event = b["events"].event(data)
#     with open(loadavg) as stats:
#         avgline = stats.read().rstrip()
#     print(("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
#         ", %d pages, loadavg: %s") % (strftime("%H:%M:%S"), event.fpid,
#         event.fcomm.decode('utf-8', 'replace'), event.tpid,
#         event.tcomm.decode('utf-8', 'replace'), event.pages, avgline))

# initialize BPF
b = BPF(text=bpf_text)
# execve_fnname = b.get_syscall_fnname("handle_mm_fault")
# print(execve_fnname)
b.attach_kprobe(event="handle_mm_fault", fn_name="do_count")
# print("Tracing OOM kills... Ctrl-C to stop.")

# header
print("Tracing... Ctrl-C to end.")

# output
try:
    sleep(interval)
except KeyboardInterrupt:
    pass

print("\n%-26s %8s" % ("FILENAME", "COUNT"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%-26s %8d" % (k.filename.decode('utf-8', 'replace'), v.value))



# b["events"].open_perf_buffer(print_event)
# while 1:
#     try:
#         b.perf_buffer_poll()
#     except KeyboardInterrupt:
#         exit()
