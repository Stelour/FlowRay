# FlowRay v0.2.0

Linux application network activity analyzer

> FlowRay inspects network sockets belonging to a specific Linux application and maps them back to the processes that own them..

## Build

**Requirements:**
- Linux
- C++20 compiler
- CMake
- Git

git clone https://github.com/Stelour/FlowRay.git
cd FlowRay

cmake -S . -B build
cmake --build build

**Run:**

./build/flowray --help

## Usage

### Target selection

#### `--pid (-p)`

Analyzes sockets belonging to the specified process.

FlowRay reads the process file descriptors from /proc/<PID>/fd, finds socket inodes owned by the process, and retrieves their socket information through NETLINK_SOCK_DIAG.

./flowray --pid 12345

#### `--name (-n)`

Analyze processes by their process name.

FlowRay scans /proc, reads /proc/<PID>/comm, and selects all processes whose name exactly matches the specified value.

> Unlike --pid, this option may select multiple processes.

./flowray --name Discord

### Additional flags

#### `--tree (-t)`

Include descendant processes of the selected process or process name.

FlowRay recursively discovers child processes and includes their socket file descriptors in the analysis.

This is useful for applications that spawn helper, worker, renderer, or other child processes.

./flowray --pid 12345 --tree

or:

./flowray --name Discord --tree

#### `--detail (-d)`

Shows additional information for each socket:

- socket inode
- PID the socket

./flowray --pid 12345 --detail

or:

./flowray --name Discord --detail


### Example

```
flowray --name Discord --detail --tree
Processes (8)
	Name: Discord[3953]
	Name: Discord[4083]
	Name: Discord[4084]
	Name: Discord[4090]
	Name: Discord[4207]
	Name: Discord[4214]
	Name: Discord[4506]
	Name: Discord[4741]

Sockets: 6

PROTOCOL | FAMILY |  LOCAL                       REMOTE                      STATE          PIDS        INODE       

TCP        IPv4      127.0.0.1:6463              0.0.0.0:0                   LISTEN         4506        49324       
TCP        IPv4      10.8.1.4:43704              162.159.137.232:443         ESTABLISHED    4214        49210       
TCP        IPv4      10.8.1.4:47686              162.159.138.234:2083        ESTABLISHED    4214        561985      
TCP        IPv4      10.8.1.4:47462              35.186.224.39:443           ESTABLISHED    4214        34782       
TCP        IPv4      10.8.1.4:52990              162.159.135.234:443         ESTABLISHED    4214        458125      
UDP        IPv4      0.0.0.0:34754               0.0.0.0:0                   -              4506        1045546
```

In this example, --name selects all running processes named Discord.
--tree also includes their descendant processes in the analysis, while --detail adds the owning PID and socket inode to the output.

## FAQ

NETLINK_SOCK_DIAG fails after a system/kernel update

> If the Linux kernel or kernel modules were updated while the system was running, the currently running kernel may no longer match the modules installed on disk. Reboot the system and try FlowRay again.