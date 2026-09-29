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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct event);
} pending_connects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct socket_info);
} tmp_sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct socket_info);
} sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} allowed_pids SEC(".maps");

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    __u8 *allowed =
    bpf_map_lookup_elem(&allowed_pids, &pid);

    if (!allowed) {
        return 0;
    }

    int fd = (int)ctx->args[0];
    void *addr = (void *)ctx->args[1];
    // int addrlen = (int)ctx->args[2];

    __u16 family = 0;

    struct event e = {};

    if (!addr) {
        return 0;
    }

    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0) {
        return 0;
    }

    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    // e = (struct event *)bpf_ringbuf_reserve(&events,sizeof(*e),0);

    // if (!e) {
    //     return 0;
    // }

    e.pid = pid;
    e.tid = tid;
    e.fd = fd;
    e.family = family;

    bpf_get_current_comm(e.comm, sizeof(e.comm));

    if (family == AF_INET) {
        struct sockaddr_in addr4 = {};

        if (bpf_probe_read_user(&addr4,sizeof(addr4), addr) < 0) {
            // bpf_ringbuf_discard(e, 0);
            return 0;
        }

        // __builtin_memset(e, 0, sizeof(*e));
        __builtin_memcpy(e.remote_addr, &addr4.sin_addr, sizeof(addr4.sin_addr));
        e.remote_port = bpf_ntohs(addr4.sin_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr6 = {};

        if (bpf_probe_read_user(&addr6, sizeof(addr6), addr) < 0) {
            // bpf_ringbuf_discard(e, 0);
            return 0;
        }

        __builtin_memcpy(e.remote_addr, &addr6.sin6_addr, sizeof(addr6.sin6_addr));
        e.remote_port = bpf_ntohs(addr6.sin6_port);
    }
    // bpf_ringbuf_submit(e, 0);

    __u64 key = ((__u64)pid << 32) | (__u32)fd;

    struct socket_info *info = bpf_map_lookup_elem(&sockets, &key);

    if (info) {
        e.type = info->type;
        e.protocol = info->protocol;
    }

    bpf_map_update_elem(&pending_connects,  &id, &e,  BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct event *pend = (struct event *)bpf_map_lookup_elem(&pending_connects, &id);

    if (!pend) {
        return 0;
    }

    long ret = ctx->ret;
    pend->result = ret;

    bpf_ringbuf_output(&events, pend, sizeof(*pend), 0);
    bpf_map_delete_elem(&pending_connects, &id);

    return 0;
}

/*
struct tracepoint__syscalls__sys_enter_socket {
    unsigned long long common_tp_fields;
    int __syscall_nr;
    long family;
    long type;
    long protocol;
};
*/

SEC("tp/syscalls/sys_enter_socket")
int handle_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct socket_info info = {};

    info.family = ctx->args[0];
    info.type = ctx->args[1];
    info.protocol = ctx->args[2];

    bpf_map_update_elem(&tmp_sockets, &id, &info, BPF_ANY);

    return 0;
}

/*
struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    long int id;
    long int ret;
    char __data[0];
};
*/

SEC("tp/syscalls/sys_exit_socket")
int handle_socket_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct socket_info *info = bpf_map_lookup_elem(&tmp_sockets, &id);

    if (!info) {
        return 0;
    }

    __u32 pid = id >> 32;
    int fd = (int)ctx->ret;

    if (fd >= 0) {
        __u64 key = ((__u64)pid << 32) | (__u32)fd;

        bpf_map_update_elem(&sockets, &key, info, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_sockets, &id);

    return 0;
}

/*

struct trace_event_raw_sys_enter_close {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    long fd;
};

*/