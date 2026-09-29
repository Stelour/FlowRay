// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.c

#include "ebpf.h"
#include "ebpf_monitor.h"
#include "ebpf_connect.skel.h"

#include <iostream>
#include <csignal>
#include <cerrno>
#include <string>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int) {
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const event *e = static_cast<const struct event *>(data);

    char remote_ip[INET6_ADDRSTRLEN]{};

    inet_ntop(
        e->family,
        e->remote_addr,
        remote_ip,
        sizeof(remote_ip)
    );

    std::string res_from_struct;

    if (e->result == 0) {
        res_from_struct = "SUCCESS";
    }
    else if (e->result == -EINPROGRESS) {
        res_from_struct = "PENDING";
    }
    else {
        res_from_struct = "FAILED";
    }

    std::cout << "PID: " << e->pid << " COMM: " << e->comm << " RESULT: " << res_from_struct << " FAMILY: " << e->family
    << " ADDR: " << remote_ip << ":" << e->remote_port << std::endl;

    return 0;
}

int ebpf_start() {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    int err;

    struct ebpf_connect_bpf* skel = ebpf_connect_bpf__open();;
    if (!skel) {
        std::cerr << "Failed to open BPF skeleton" << std::endl;
        return 1;
    }

    err = ebpf_connect_bpf__load(skel);
    if (err) {
        std::cerr << "Failed to load BPF skeleton: " << err << std::endl;
        ebpf_connect_bpf__destroy(skel);
        return 1;
    }

    err = ebpf_connect_bpf__attach(skel);

    if (err) {
        std::cerr << "Failed to attach BPF skeleton: " << err << std::endl;
        ebpf_connect_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        ebpf_connect_bpf__destroy(skel);
        return 1;
    }

    std::cout << "FlowRay eBPF monitor started" << std::endl;

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err == -EINTR) {
            break;
        }

        if (err < 0) {
            std::cerr << "Error polling perf buffer: " << err << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    ebpf_connect_bpf__destroy(skel);

    return 0;
}