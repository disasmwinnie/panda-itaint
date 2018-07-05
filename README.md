Plugin: panda-itaint
===========

Summary
-------

``panda_itaint`` (input taint) is a [PANDA2](https://github.com/panda-re/panda/) plugin, which determines which data to be tainted, by parsing Linux syscalls responsible for file reading respectively receiving network traffic.

The plugin itself can be used to extract the values of syscalls. For taint analysis, however, the plugin is pretty much useless on itself. It has to be used in conjunction with other analysis plugins, which leverages the taint information. Look at moyix\'s [file_taint asciinema example](https://asciinema.org/a/130615) to see how it can be used.

In contrast to the ``file_taint`` plugin it does not support filtering file reading syscalls by file name.
Instead itaint catches **all** relevant syscalls and outputs useful function arguments. Among them:

* file/socket descriptor
* buffer address and size
* length of actually received bytes (return value)
* in case of files, the file name
* the file respectively packet content

Every relevant syscall is identified by an iterating number.
One is expected to utilize PANDA2\'s Record&Replay feature in order to use itaint. At first, the syscall(s) to be tainted is chosen and during the second replay, the taint is actually triggered.

The plugin offers a cmdline argument to choose between tracing/tainting of file reading or receiving network traffic.
Since read() is used for network and files, the plugin additionally tracks all socket() and open() calls in order to distinguish which ones to track.

Currently, the plugin supports the x86 and ARM platform. The Later is, at this point, not tested.

``panda_itaint`` supports the following syscalls:

* preadv (x86 specific)
* socketcall (specific to Linux-x86, wrapper around and used instead socket, recv, recvfrom, recvmsg)
* socket
* recv
* recvfrom
* recvmsg
* read
* read64
* readv
* open
* close

Arguments
---------

* **action**: Choose action for itaint (required). *parse_syscalls* to parse syscalls, *taint* parse all syscalls and taint them (if no specific one is selected, see *syscall_nrs*)
* **syscall\_nrs** One or a list of dash separated (comma and space already reserved) integers to limit the amount of tainted syscalls. This cmdline argument can be used, after running a replay with the *parse_syscalls* parameter. All parsed syscalls are iterated with a number, starting at zero.

* **msg\_type** Choose which kind of messages should be parsed, choose either *file* for read files, or *network* (default) for received messages.

* (Currently broken) **collect_procs** collectes the names of all executed process during the recording and outputs them during the execution.

* (Currently broken) **proc\_name**: Limit the syscall parsing respectively tainting to desired process.

Dependencies
------------
``itaint`` depends on the **osi**, **osi\_linux** and **syscalls2** plugins in order to parse syscalls. And, when tainting is activated the **taint2** plugin.

Known Issues
------------------

Collection and setting of process names is currently broken. It supposed to be a goodie in order to accelerate the initial finding of desired syscall.

Example
-------

Record a trace:

```bash
$ export PANDABIN=~/git/panda/build/i386-softmmu/qemu-system-i386

$ $PANDABIN -hda $PATHTOVMS/debian7_x86.qcow2 -monitor telnet:localhost:2222,server,nowait -vga std -display sdl -m 512 -netdev user,id=eth11,hostfwd=tcp::1122-:22 -device rtl8139,netdev=eth11 -replay ~/BIND9 -os linux-32-debian-3.2.81-686-pae -panda panda-itaint:help

PANDA[core]: os_familyno=2 bits=32 os_details=debian-3.2.81-686-pae
PANDA[panda-itaint]: adding argument help.
PANDA[core]: initializing panda-itaint
Options for plugin panda-itaint:
PLUGIN              ARGUMENT                REQUIRED        DESCRIPTION
======              ========                ========        ===========
--]] panda-itaint plugin loaded [[--
panda-itaint        action                  Required        Choose action for itaint: parse_syscalls, taint, collect_procs
panda-itaint        proc_name               Optional        Process name, which should be tracked for tainting (default="(null)")
panda-itaint        msg_type                Optional        Which kind of messages should be parsed, choose either'file' for read files, or 'network'(default). (default="network")
panda-itaint        syscall_nrs             Optional        Catched syscalls are incremented. Give predefined, dash separatedlist of syscall numbers that should trigger tainting. (default="(null)")
```

The itaint plugin is supposed to work by first using **action=parse_syscalls** and the finding the desired syscall, to be tainted. Afterwards, specifying the syscall with **syscall_nrs=0-2-68** and enable tainting with **action=taint**.

```bash
$ $PANDABIN -hda $PATHTOVMS/debian7_x86.qcow2 -monitor telnet:localhost:2222,server,nowait -vga std -display sdl -m 512 -netdev user,id=eth11,hostfwd=tcp::1122-:22 -device rtl8139,netdev=eth11 -replay ~/BIND9 -os linux-32-debian-3.2.81-686-pae -panda panda-itaint:action=parse_syscalls,msg_type=network
```

```
[...]
[ITAINT](NFO): socketcall entered desired proc.
[ITAINT](NFO): recv(from) encountered.
  DBG: recv socket: 6
  DBG: buf_addr: 3109068288
  DBG: buf_size: 65536
  DBG: flags: 0
  RECV leng: 45
  Base64 encoded message:
9uaBgAABAAEAAAAAB21zZ3BlZWsDbmV0AAABAAHADAABAAEAAAcHAASKyXQE
[ITAINT](NFO): CURRENT SYSCALL NR:
50
[...]
```

Examine the content of the packets and decide which ones to taint.
Note, the output can get very large. You might want to pipe it into a file.

```
echo "9uaBgAABAAEAAAAAB21zZ3BlZWsDbmV0AAABAAHADAABAAEAAAcHAASKyXQE" | base64 -d | hexdump -C
00000000  f6 e6 81 80 00 01 00 01  00 00 00 00 07 6d 73 67  |.............msg|
00000010  70 65 65 6b 03 6e 65 74  00 00 01 00 01 c0 0c 00  |peek.net........|
00000020  01 00 01 00 00 07 07 00  04 8a c9 74 04           |...........t.|
0000002d
```

Change **action** to *taint* and set the syscall number -> profit.
```bash
$ $PANDABIN -hda $PATHTOVMS/debian7_x86.qcow2 -monitor telnet:localhost:2222,server,nowait -vga std -display sdl -m 512 -netdev user,id=eth11,hostfwd=tcp::1122-:22 -device rtl8139,netdev=eth11 -replay ~/BIND9 -os linux-32-debian-3.2.81-686-pae -panda panda-itaint:action=taint,msg_type=network,syscall_nrs=50
```

This also works in a similar way for parsing read files.

```
[...]
> [ITAINT](NFO): read() encountered.
> [ITAINT](ERR): The read()-syscall returned -1 or 0.
> [ITAINT](NFO): close() encountered.
> [ITAINT](NFO): Socket CLOSED:
> 6
> [ITAINT](NFO): open() encountered.
> [ITAINT](NFO): DBG: file descriptor OPENED:
> 6
> [ITAINT](NFO):  Corresponding file_name is:
> /etc/hosts
> [ITAINT](NFO):  Corresponding flags-var is:
> 524288
> [ITAINT](NFO): read() encountered.
> [ITAINT](NFO): RET:
> 188
>         DBG: recv socket: 6
>         DBG: buf_addr: 3077705728
>         DBG: buf_size: 4096
>         DBG: flags: 0
>         RECV leng: 188
>         Base64 encoded message:
> MTI3LjAuMC4xCWxvY2FsaG9zdAoxMjcuMC4xLjEJZGViaWFudm0KCiMgVGhlIGZvbGxvd2luZyBsaW5lcyBhcmUgZGVzaXJhYmxlIGZvciBJUHY2IGNhcGFibGUgaG9zdHMKOjoxICAgICBsb2NhbGhvc3QgaXA2LWxvY2FsaG9zdCBpcDYtbG9vcGJhY2sKZmYwMjo6MSBpcDYtYWxsbm9kZXMKZmYwMjo6MiBpcDYtYWxscm91dGVycwo=
[...]
```

```
$ echo "MTI3LjAuMC4xCWxvY2FsaG9zdAoxMjcuMC4xLjEJZGViaWFudm0KCiMgVGhlIGZvbGxvd2luZyBsaW5lcyBhcmUgZGVzaXJhYmxlIGZvciBJUHY2IGNhcGFibGUgaG9zdHMKOjoxICAgICBsb2NhbGhvc3QgaXA2LWxvY2FsaG9zdCBpcDYtbG9vcGJhY2sKZmYwMjo6MSBpcDYtYWxsbm9kZXMKZmYwMjo6MiBpcDYtYWxscm91dGVycwo=" | base64 -d

> 127.0.0.1	localhost
> 127.0.1.1	debianvm
>
> # The following lines are desirable for IPv6 capable hosts
> ::1     localhost ip6-localhost ip6-loopback
> ff02::1 ip6-allnodes
> ff02::2 ip6-allrouters
```
