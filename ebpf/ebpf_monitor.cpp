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
#include <chrono>
#include <unordered_set>
#include <net/if.h>

struct tcx_links {
    unsigned int ifindex = 0;
    std::string ifname;

    bpf_link* ingress = nullptr;
    bpf_link* egress = nullptr;
};

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

    std::string prt;
    if (e->protocol == IPPROTO_TCP) {
        prt = "TCP";
    } else if (e->protocol == IPPROTO_UDP) {
        prt = "UDP";
    } else {
        prt = "UNKNOWN";
    }

    std::cout << "PID: " << e->pid << " COMM: " << e->comm << " RESULT: " << res_from_struct << " FAMILY: " << e->family
    << " ADDR: " << remote_ip << ":" << e->remote_port
    << " PROTOCOL: " << prt << std::endl;

    return 0;
}

static int update_proc(struct ebpf_connect_bpf* skel, std::unordered_set<std::uint32_t>& tracked_pids,
    bool pid_tree, const std::string& proc_name) {
    if (tracked_pids.empty()) {
        return 1;
    }

    if (!pid_tree && proc_name.empty()) {
        if (!std::filesystem::is_directory("/proc/" + std::to_string(*tracked_pids.begin()))) {
            return 1;
        }
        return 0;
    }

    std::vector<std::uint32_t> cur;
    if (!proc_name.empty()) {
        cur = find_pids_by_name(proc_name);
    } else {
        for (auto pid : tracked_pids) {
            if (std::filesystem::is_directory("/proc/" + std::to_string(pid))) {
                cur.push_back(pid);
            }
        }
    }

    if (pid_tree) {
        for (auto pid : cur) {
            push_pid_tree(pid, cur);
        }
        std::sort(cur.begin(), cur.end());
        cur.erase(
            std::unique(cur.begin(), cur.end()),
            cur.end()
        );
    }

    // std::vector<std::uint32_t> dropped;
    // for (const auto& old_pid : tracked_pids) {
    //     bool found = false;
    //
    //     for (const auto& new_pid : cur) {
    //         if (old_pid == new_pid) {
    //             found = true;
    //             break;
    //         }
    //     }
    //
    //     if (!found) {
    //         err = bpf_map_delete_elem(bpf_map__fd(skel->maps.allowed_pids), &old_pid);
    //         if (err) {
    //             std::cerr << "Failed to update element for PID (update_proc): " << old_pid << std::endl;
    //             cur.push_back(old_pid);
    //         }
    //     }
    // }
    //
    // for (const auto& new_pid : cur) {
    //     bool found = false;
    //
    //     for (const auto& old_pid : tracked_pids) {
    //         if (new_pid == old_pid) {
    //             found = true;
    //             break;
    //         }
    //     }
    //
    //     if (!found) {
    //         err = bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_pids), &new_pid, &value, BPF_ANY);
    //         if (err) {
    //             std::cerr << "Failed to update element for PID (update_proc): " << new_pid << std::endl;
    //             dropped.push_back(new_pid);
    //         }
    //     }
    // }
    //
    // if (!dropped.empty()) {
    //     for (const auto& dele : dropped) {
    //         std::erase(cur, dele);
    //     }
    // }
    //
    // tracked_pids = cur;

    std::unordered_set current_pids(cur.begin(), cur.end());
    std::uint8_t value = 1;
    int alwfd = bpf_map__fd(skel->maps.allowed_pids);
    for (auto it = tracked_pids.begin(); it != tracked_pids.end();) {
        std::uint32_t pid = *it;
        if (!current_pids.contains(pid)) {
            int err = bpf_map_delete_elem(alwfd, &pid);
            if (err) {
                std::cerr << "Failed delete PID " << pid << std::endl;
                ++it;
            } else {
                it = tracked_pids.erase(it);
            }
        } else {
            ++it;
        }
    }

    for (auto pid : current_pids) {
        if (!tracked_pids.contains(pid)) {
            int err = bpf_map_update_elem(alwfd, &pid, &value, BPF_ANY);
            if (err) {
                std::cerr << "Failed add PID " << pid << std::endl;
            } else {
                tracked_pids.insert(pid);
            }
        }
    }

    return 0;
}

static int attach_tcx_interfaces(struct ebpf_connect_bpf* skel, std::vector<tcx_links>& attached) {
    struct if_nameindex* ifs = if_nameindex();

    if (!ifs) {
        std::cerr << "Failed to get network interfaces" << std::endl;
        return 1;
    }

    for (struct if_nameindex* it = ifs; it->if_index != 0 && it->if_name != nullptr; ++it) {
        bpf_tcx_opts opts{};
        opts.sz = sizeof(opts);

        tcx_links links{};
        links.ifindex = it->if_index;
        links.ifname = it->if_name;

        links.ingress = bpf_program__attach_tcx(skel->progs.handle_ingress, it->if_index, &opts);

        if (!links.ingress) {
            std::cerr << "Failed to attach TCX ingress to " << it->if_name << std::endl;
            continue;
        }

        links.egress = bpf_program__attach_tcx(skel->progs.handle_egress, it->if_index, &opts);

        if (!links.egress) {
            std::cerr << "Failed to attach TCX egress to " << it->if_name << std::endl;
            bpf_link__destroy(links.ingress);
            continue;
        }

        std::cout << "TCX attached: " << it->if_name << " (ifindex " << it->if_index << ")\n";
        attached.push_back(std::move(links));
    }
    if_freenameindex(ifs);
    return attached.empty() ? 1 : 0;
}

static void print_flow_metrics(struct ebpf_connect_bpf* skel) {
    int map_fd = bpf_map__fd(skel->maps.flow_mtr);

    flow_key current_key{};
    flow_key next_key{};

    const flow_key* current = nullptr;

    while (bpf_map_get_next_key(map_fd, current, &next_key) == 0) {
        flow_metrics metrics{};

        if (bpf_map_lookup_elem(map_fd, &next_key, &metrics) == 0) {
            char remote_ip[INET6_ADDRSTRLEN]{};
            const void* addr = next_key.remote_addr;
            if (inet_ntop(next_key.family, addr, remote_ip, sizeof(remote_ip))) {
                std::cout << "TRAFFIC " << remote_ip << " | RX: " << metrics.rx_bytes
                    << " bytes / " << metrics.rx_packets << " packets | TX: " << metrics.tx_bytes
                    << " bytes / " << metrics.tx_packets << " packets" << std::endl;
            }
        }
        current_key = next_key;
        current = &current_key;
    }
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

    bpf_program__set_autoattach(skel->progs.handle_ingress, false);
    bpf_program__set_autoattach(skel->progs.handle_egress, false);

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

    std::vector<tcx_links> tcx_attached;

    err = attach_tcx_interfaces(skel, tcx_attached);

    if (err) {
        std::cerr << "Failed to attach TCX to network interfaces" << std::endl;
        ebpf_connect_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        ebpf_connect_bpf__destroy(skel);
        return 1;
    }

    std::unordered_set<std::uint32_t> tracked_pids;
    std::uint8_t value = 1;
    for (auto pid : procs_pid) {
        int err = bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_pids), &pid, &value, BPF_ANY);
        if (err) {
            std::cerr << "Failed to update element for PID: " << pid << std::endl;
        } else {
            tracked_pids.insert(pid);
        }
    }

    std::cout << "FlowRay eBPF monitor started" << std::endl;

    auto last_scan = std::chrono::steady_clock::now();
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err == -EINTR) {
            break;
        }

        if (err < 0) {
            std::cerr << "Error polling perf buffer: " << err << std::endl;
            break;
        }

        auto now = std::chrono::steady_clock::now();

        if (now - last_scan > std::chrono::seconds(1)) {
            err = update_proc(skel, tracked_pids, pid_tree, proc_name);
            std::cout << "\n--- Traffic ---\n";
            print_flow_metrics(skel);
            std::cout << "---------------\n\n";
            last_scan = now;
        }
    }

    ring_buffer__free(rb);

    for (auto& links : tcx_attached) {
        if (links.ingress) {
            bpf_link__destroy(links.ingress);
        }

        if (links.egress) {
            bpf_link__destroy(links.egress);
        }
    }

    ebpf_connect_bpf__destroy(skel);

    return 0;
}
