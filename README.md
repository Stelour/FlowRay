# FlowRay v0.1.1

Linux application network activity analyzer

> FlowRay is a Linux networking tool for inspecting network activity of a specific process.

## Usage

### 1: --pid

Analyzes sockets belonging to the specified process.

Example:
```
./flowray --pid 148615

PID: 148615
Process name: Telegram

Sockets: 3

PROTOCOL | FAMILY |  LOCAL                       REMOTE                      STATE          

TCP        IPv4      10.8.1.4:39292              91.105.192.100:443          ESTABLISHED    
TCP        IPv4      10.8.1.4:51944              149.154.167.51:443          ESTABLISHED    
TCP        IPv4      10.8.1.4:53036              149.154.167.41:443          ESTABLISHED 
```

#### 1.1: --pid --tree (-t)

Recursive child process scanning.

#### 1.2: --pid --detail (-d)

Detailed information about socket.

Example:
```
./flowray --pid 4308 --tree --detail

PID: 4308
Process name: Discord

Sockets: 6

PROTOCOL | FAMILY |  LOCAL                       REMOTE                      STATE          PIDS                INODE       

TCP        IPv4      127.0.0.1:6463              0.0.0.0:0                   LISTEN         4784                1010199     
TCP        IPv4      10.8.1.4:54824              162.159.136.232:443         ESTABLISHED    4613                1148994     
TCP        IPv4      10.8.1.4:42642              162.159.129.235:2096        ESTABLISHED    4613                1161365     
TCP        IPv4      10.8.1.4:48998              162.159.133.234:443         ESTABLISHED    4613                1153531     
TCP        IPv4      10.8.1.4:44788              35.186.224.39:443           ESTABLISHED    4613                1187344     
UDP        IPv4      0.0.0.0:46811               0.0.0.0:0                   -              4784                1718912
```

## FAQ

NETLINK_SOCK_DIAG fails after a system/kernel update

> If the Linux kernel or kernel modules were updated while the system was running, the currently running kernel may no longer match the modules installed on disk. Reboot the system and try FlowRay again.