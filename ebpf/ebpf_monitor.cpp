// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.c

#include "ebpf.h"
#include "ebpf_monitor.h"
#include "ebpf_connect.skel.h"
#include "../headers/proc_name.h"
#include "../headers/pid.h"
#include "../headers/output.h"

#include <iostream>
#include <csignal>
#include <cerrno>
#include <cstdint>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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
        return 0;
    }

    int base_type = e->type & 0xF;
    std::string prt;

    if (e->protocol == IPPROTO_TCP) {
        prt = "TCP";
    } else if (e->protocol == IPPROTO_UDP) {
        prt = "UDP";
    } else if (e->protocol == 0 && base_type == SOCK_STREAM) {
        prt = "TCP";
    } else if (e->protocol == 0 && base_type == SOCK_DGRAM) {
        prt = "UDP";
    } else {
        prt = "UNKNOWN";
    }

    std::cout << "PID: " << e->pid << " COMM: " << e->comm << " RESULT: " << res_from_struct << " FAMILY: " << e->family
    << " ADDR: " << remote_ip << ":" << e->remote_port
    << " PROTOCOL: " << prt << std::endl;

    return 0;
}

int ebpf_start(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::vector<std::uint32_t> procs_pid = pids;
    if (pid_tree) {
        for (auto pid : procs_pid) {
            push_pid_tree(pid, procs_pid);
        }
        std::sort(procs_pid.begin(), procs_pid.end());
        procs_pid.erase(
            std::unique(procs_pid.begin(), procs_pid.end()),
            procs_pid.end()
        );
    }

    std::cout << "PIDS: (" << procs_pid.size() << ")" << std::endl << "\t";
    for (auto pid : procs_pid) {
        std::cout << pid << " ";
    }
    std::cout << std::endl << std::endl;

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

    std::uint8_t value = 1;
    for (auto pid : procs_pid) {
        int err = bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_pids), &pid, &value, BPF_ANY);
        if (err) {
            std::cerr << "Failed to update element for PID: " << pid << std::endl;
        }
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