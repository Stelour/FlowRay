// https://github.com/libbpf/libbpf-bootstrap/tree/master/examples/c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.bpf.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.bpf.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/kprobe.bpf.c

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"

// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ebpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    int fd = (int)ctx->args[0];
    void *addr = (void *)ctx->args[1];
    // int addrlen = (int)ctx->args[2];

    __u16 family = 0;

    struct event *e;

    if (!addr) {
        return 0;
    }

    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0) {
        return 0;
    }

    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    e = (struct event *)bpf_ringbuf_reserve(&events,sizeof(*e),0);

    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->fd = fd;
    e->family = family;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    if (family == AF_INET) {
        struct sockaddr_in addr4 = {};

        if (bpf_probe_read_user(&addr4,sizeof(addr4), addr) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }

        // __builtin_memset(e, 0, sizeof(*e));
        __builtin_memcpy(e->remote_addr, &addr4.sin_addr, sizeof(addr4.sin_addr));
        e->remote_port = bpf_ntohs(addr4.sin_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr6 = {};

        if (bpf_probe_read_user(&addr6, sizeof(addr6), addr) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }

        __builtin_memcpy(e->remote_addr, &addr6.sin6_addr, sizeof(addr6.sin6_addr));
        e->remote_port = bpf_ntohs(addr6.sin6_port);
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}