#ifndef FLOWRAY_EBPF_H
#define FLOWRAY_EBPF_H

#define FLOWRAY_COMM_LEN 16
#define FLOWRAY_ADDR_LEN 16

#define AF_INET 2
#define AF_INET6 10

struct event {
    unsigned int pid;
    unsigned int tid;

    int fd;

    unsigned short family;
    unsigned short remote_port;

    unsigned char remote_addr[FLOWRAY_ADDR_LEN];

    char comm[FLOWRAY_COMM_LEN];

    int result;
};

#endif //FLOWRAY_EBPF_H
