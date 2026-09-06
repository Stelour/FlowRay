# FlowRay

FlowRay is a Linux networking tool for inspecting network activity of a specific process.

> Linux application network activity analyzer

## Usage

### 1: --pid

Analyzes sockets belonging to the specified process.

FlowRay finds socket inodes through /proc/<PID>/fd, queries socket information from the kernel using NETLINK_SOCK_DIAG, and matches the results back to the process.

Example:
```
./flowray --pid 686955

PID: 686955
Process name: Telegram

Sockets:
TCP	IPv4	10.8.1.4:40500 -> 149.154.167.41:443
TCP	IPv4	10.8.1.4:40504 -> 149.154.167.41:443
TCP	IPv4	10.8.1.4:54154 -> 91.105.192.100:443
```

## FAQ

NETLINK_SOCK_DIAG fails after a system/kernel update

> If the Linux kernel or kernel modules were updated while the system was running, the currently running kernel may no longer match the modules installed on disk. Reboot the system and try FlowRay again.