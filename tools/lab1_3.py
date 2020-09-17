#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# filelife    Trace the lifespan of short-lived files.
#             For Linux, uses BCC, eBPF. Embedded C.
#
# This traces the creation and deletion of files, providing information
# on who deleted the file, the file age, and the file name. The intent is to
# provide information on short-lived files, for debugging or performance
# analysis.
#
# USAGE: filelife [-h] [-p PID]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Feb-2015   Brendan Gregg   Created this.
# 17-Feb-2016   Allan McAleavy updated for BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filelife           # trace all stat() syscalls
    ./filelife -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace stat() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 rwflag;
    u32 pid;
    char mode[32];
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
    u64 ip;

};

//BPF_HASH(birth, struct dentry *);
BPF_PERF_OUTPUT(events);

int read_trace(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER
    struct data_t data = {};
    data.ip = PT_REGS_IP(ctx);

    //u64 ts = bpf_ktime_get_ns();
    //birth.update(&dentry, &ts);
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    int mode = file->f_inode->i_mode;
    if(S_ISDIR(mode))
        strcpy(data.mode,"DIRECTORY");
    else if(S_ISCHR(mode))
        strcpy(data.mode,"CHARACTER SPECIAL");
    else if(S_ISBLK(mode))
        strcpy(data.mode,"BLOCK SPECIAL");
    else if(S_ISREG(mode))
        strcpy(data.mode,"REGULAR");
    else if(S_ISFIFO(mode))
        strcpy(data.mode,"FIFO SPECIAL/PIPE");
    else if(S_ISLNK(mode))
        strcpy(data.mode,"SYMBOLIC LINK");
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        data.pid = pid;
        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
    }
    data.rwflag = 0;  // read
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};

int write_trace(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER
    struct data_t data = {};
    data.ip = PT_REGS_IP(ctx);

    //u64 ts = bpf_ktime_get_ns();
    //birth.update(&dentry, &ts);
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    int mode = file->f_inode->i_mode;
    if(S_ISDIR(mode))
        strcpy(data.mode,"DIRECTORY");
    else if(S_ISCHR(mode))
        strcpy(data.mode,"CHARACTER SPECIAL");
    else if(S_ISBLK(mode))
        strcpy(data.mode,"BLOCK SPECIAL");
    else if(S_ISREG(mode))
        strcpy(data.mode,"REGULAR");
    else if(S_ISFIFO(mode))
        strcpy(data.mode,"FIFO SPECIAL/PIPE");
    else if(S_ISLNK(mode))
        strcpy(data.mode,"SYMBOLIC LINK");

    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        data.pid = pid;
        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
    }
    data.rwflag = 1;  // write
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
# b.attach_kprobe(event="vfs_create", fn_name="trace_create")
# # newer kernels (say, 4.8) may don't fire vfs_create, so record (or overwrite)
# # the timestamp in security_inode_create():
# b.attach_kprobe(event="security_inode_create", fn_name="trace_create")
# b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")

b.attach_kprobe(event="vfs_read", fn_name="read_trace")
b.attach_kprobe(event="vfs_readv", fn_name="read_trace")
b.attach_kprobe(event="vfs_write", fn_name="write_trace")
b.attach_kprobe(event="vfs_writev", fn_name="write_trace")

# header
print("%-8s %-6s %-16s %-10s %-7s %s" % ("TIME", "PID", "COMM", "READ/WRITE", "AGE(s)", "FILE"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    # print("%-8s %-6d %-16s %-7.2f %s" % (strftime("%H:%M:%S"), event.pid,
    #     event.comm.decode('utf-8', 'replace'), float(event.delta) / 1000,
    #     event.fname.decode('utf-8', 'replace')))
    rw = ""
    if event.rwflag==0:
        rw = "READ"
    else:
        rw = "WRITE"
    print(b.ksym(event.ip))
    print("%-8s %-6d %-10s %-16s %-16s %-32s" % (strftime("%H:%M:%S"), event.pid, rw,
        event.comm.decode('utf-8', 'replace'),
        event.fname.decode('utf-8', 'replace'), event.mode))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
