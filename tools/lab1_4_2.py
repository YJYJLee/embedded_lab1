#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import signal
from subprocess import call

interval = 99999999

# linux stats
diskstats = "/proc/diskstats"

# signal handler
def signal_ignore(signal_value, frame):
    print()

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

// for saving process info by request
struct who_t {
    u32 pid;
    u64 sector;
    u64 len;
    char name[TASK_COMM_LEN];
};

// the key for the output summary
struct info_t {
    u32 pid;
    int rwflag;
    int major;
    int minor;
    char name[TASK_COMM_LEN];
};

// the value of the output summary
struct val_t {
    u64 prev;
    u64 seq_rcount;
    u64 seq_wcount;
    u64 rand_rcount;
    u64 rand_wcount;
};

BPF_HASH(start, struct request *);
BPF_HASH(whobyreq, struct request *, struct who_t);
BPF_HASH(counts, struct info_t, struct val_t);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct who_t who = {};

    if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0) {
        who.pid = bpf_get_current_pid_tgid() >> 32;
        who.len = req->__data_len;
        who.sector = req->__sector;
        whobyreq.update(&req, &who);
    }

    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;    // missed tracing issue
    }

    struct who_t *whop;
    struct val_t *valp, zero = {};
    u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // setup info_t key
    struct info_t info = {};
    info.major = req->rq_disk->major;
    info.minor = req->rq_disk->first_minor;
/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    info.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    info.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    info.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    whop = whobyreq.lookup(&req);
    if (whop == 0) {
        // missed pid who, save stats as pid 0
        valp = counts.lookup_or_try_init(&info, &zero);
    } else {
        info.pid = whop->pid;
        __builtin_memcpy(&info.name, whop->name, sizeof(info.name));
        valp = counts.lookup_or_try_init(&info, &zero);
    }

    if (valp) {
        // save stats
        u64 cur_sector;
        u64 cur_len;
        bpf_probe_read_kernel(&cur_sector, sizeof(cur_sector), &whop->sector);
        bpf_probe_read_kernel(&cur_len, sizeof(cur_len), &whop->len);
        if (valp->prev == cur_sector || valp->prev == 0) {
            if(info.rwflag==1){
                valp->seq_wcount++;
            }
            else{
                valp->seq_rcount++;
            }
        }
        else{
            if(info.rwflag==1){
                valp->rand_wcount++;
            }
            else{
                valp->rand_rcount++;
            }
        }
        valp->prev = cur_len/512 + cur_sector;
    }

    start.delete(&req);
    whobyreq.delete(&req);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_done",
    fn_name="trace_req_completion")

print('Tracing... Hit Ctrl-C to end.')

# cache disk major,minor -> diskname
disklookup = {}
with open(diskstats) as stats:
    for line in stats:
        a = line.split()
        disklookup[a[0] + "," + a[1]] = a[2]

# output
exiting = 0
try:
    sleep(interval)
except KeyboardInterrupt:
    exiting = 1

print("\n%-6s %-16s %-3s %-3s %-8s %-10s %-10s %-10s %-10s" % ("PID", "COMM", "MAJ", "MIN", "DISK", "SEQ_READ", "SEQ_WRITE", "RAND_READ", "RAND_WRITE"))

# by-PID output
counts = b.get_table("counts")
for k, v in reversed(sorted(counts.items(),
                            key=lambda counts: counts[1].seq_rcount)):

    # lookup disk
    disk = str(k.major) + "," + str(k.minor)
    if disk in disklookup:
        diskname = disklookup[disk]
    else:
        diskname = "?"

    if diskname=="sda":
        print("%-6s %-16s %-3d %-3d %-8s %-10s %-10s %-10s %-10s" % (k.pid,
            k.name.decode('utf-8', 'replace'),
            k.major, k.minor, diskname, v.seq_rcount, v.seq_wcount, v.rand_rcount, v.rand_wcount))