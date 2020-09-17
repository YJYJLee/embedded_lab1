#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime

def parse_uid(user):
    try:
        result = int(user)
    except ValueError:
        try:
            user_info = pwd.getpwnam(user)
        except KeyError:
            raise argparse.ArgumentTypeError(
                "{0!r} is not valid UID or user entry".format(user))
        else:
            return user_info.pw_uid
    else:
        # Maybe validate if UID < 0 ?
        return result


# arguments
examples = """examples:
    ./lab1_1.py
"""

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    int retval;
};

BPF_HASH(start, u32);
BPF_PERF_OUTPUT(events);

int syscall__io_schedule(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct data_t data = {};

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // create data here and pass to submit_arg to save stack space (#555)
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    u64 ts;
    ts = bpf_ktime_get_ns();
    start.update(&data.pid, &ts);    

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;
    return 0;
}

int do_ret_sys_io_schedule(struct pt_regs *ctx)
{

    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    u64 *tsp;
    u64 ts;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&data.pid);
    
    if (tsp == 0) {
        // missed tracing issue
        return 0;
    }
    ts = bpf_ktime_get_ns();
    data.delta = ts - *tsp;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

bpf_text = bpf_text.replace("MAXARG", "20")

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="io_schedule", fn_name="syscall__io_schedule")
b.attach_kretprobe(event="io_schedule", fn_name="do_ret_sys_io_schedule")

# header
print("%-9s" % ("TIME"), end="")
print("%-8s" % ("TIME(s)"), end="")
print("%-6s" % ("UID"), end="")
print("%-16s %-6s %-6s %-3s %20s" % ("PCOMM", "PID", "PPID", "RET",  "SCHEDULED_OUT_DUR(ns)"))

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

start_ts = time.time()
argv = defaultdict(list)

# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    skip = False
    if event.type == EventType.EVENT_RET:
        if event.retval != 0:
            skip = True
        if not skip:
            printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
            printb(b"%-8.3f" % (time.time() - start_ts), nl="")
            printb(b"%-6d" % event.uid, nl="")
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            ppid = b"%d" % ppid if ppid > 0 else b"?"
            printb(b"%-16s %-6d %-6s %-3d %20d" % (event.comm, event.pid,
                   ppid, event.retval, event.delta))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
