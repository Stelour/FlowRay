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
TCP	IPv4	10.8.1.4:40500 -> 149.154.167.41:443	ESTABLISHED
TCP	IPv4	10.8.1.4:40504 -> 149.154.167.41:443	ESTABLISHED
TCP	IPv4	10.8.1.4:54154 -> 91.105.192.100:443	ESTABLISHED
```

#### 1.1: --pid --tree

Recursive child process scanning.

#### 1.2: --pid --detail

Detailed information about socket.

Example:
```
./flowray --pid 5266 --tree --detail

PID: 5266
Process name: Discord

Sockets:
TCP	IPv4	127.0.0.1:6463 -> 0.0.0.0:0	LISTEN
	PID: 6005 
	inode: 1571273
TCP	IPv4	10.8.1.4:39194 -> 162.159.137.232:443	ESTABLISHED
	PID: 5497 
	inode: 2441668
TCP	IPv4	10.8.1.4:42804 -> 35.186.224.39:443	ESTABLISHED
	PID: 5497 
	inode: 2556274
TCP	IPv4	10.8.1.4:46314 -> 162.159.136.234:443	ESTABLISHED
	PID: 5497 
	inode: 2454823
```

## FAQ

NETLINK_SOCK_DIAG fails after a system/kernel update

> If the Linux kernel or kernel modules were updated while the system was running, the currently running kernel may no longer match the modules installed on disk. Reboot the system and try FlowRay again.