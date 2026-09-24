#include "ebpf.h"

// https://github.com/libbpf/libbpf-bootstrap/tree/master/examples/c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.bpf.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid)
        return 0;

    bpf_printk("BPF triggered from PID %d.\n", pid);

    return 0;
}