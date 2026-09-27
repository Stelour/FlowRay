// https://github.com/libbpf/libbpf-bootstrap/tree/master/examples/c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.bpf.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.bpf.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/kprobe.bpf.c

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include "ebpf.h"
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    int fd = (int)ctx->args[0];
    void *addr = (void *)ctx->args[1];
    int addrlen = (int)ctx->args[2];

    char comm[16] = {};

    bpf_get_current_comm(comm, sizeof(comm));

    __u16 family = 0;

    if (!addr) {
        return 0;
    }

    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0) {
        return 0;
    }

    // if (pid != my_pid)
    //     return 0;

    // bpf_printk("connect PID=%u FD=%d FAMILY=%u.\n", pid, fd, sa.sa_family);


    if (family == AF_INET) {
        struct sockaddr_in addr_st = {};
        if (bpf_probe_read_user(&addr_st, sizeof(addr_st), addr) < 0) {
            return 0;
        }
        __u16 port = bpf_ntohs(addr_st.sin_port);
        bpf_printk("connect ipv4 PID=%u FD=%d PORT=%u", pid, fd, port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr_st = {};
        if (bpf_probe_read_user(&addr_st, sizeof(addr_st), addr) < 0) {
            return 0;
        }
        __u16 port = bpf_ntohs(addr_st.sin6_port);
        bpf_printk("connect ipv4 PID=%u FD=%d PORT=%u", pid, fd, port);
    }
    return 0;
}