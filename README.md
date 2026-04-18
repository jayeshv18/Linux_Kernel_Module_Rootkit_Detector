Rootkit & DKOM Detector

A self-defending Linux Kernel Module (LKM) engineered to detect privilege escalation and Direct Kernel Object Manipulation (DKOM) in real-time.

Built from first principles in C, this tool acts as a covert wiretap inside the kernel space (Ring-0), completely bypassing standard user-space (Ring-3) antivirus signatures. 
It monitors process execution, identifies hidden "ghost" malware, hides its own presence from system administrators, and streams telemetry securely via Netlink sockets.

How it Works:

Operating systems are divided into two worlds: User Space (where normal programs live) and Kernel Space (the absolute core of the operating system that controls the hardware).
Standard malware operates in User Space. But advanced malware called a Rootkit—infects Kernel Space. Once a rootkit is inside the kernel, it can lie to the antivirus, hide its files, and grant the hacker ultimate "God Mode" access.

This project fights fire with fire. It is a kernel module that sits in Ring-0 and acts like an invisible security camera.

The Four Pillars of the Architecture:
1. The Wiretap (kprobes & execve)
Every time you run a command in Linux (like ls or pwd), the system must eventually call a core kernel function named __x64_sys_execve. This is the single doorway every program must walk through to execute.

The Analogy: We place a physical tripwire (a kprobe) across this doorway. Every time a program walks through, our trap pauses the program, takes its photo, and checks its ID before letting it run.

2. The Logic Engine (The Traps)
When the tripwire fires, we analyze the suspect's DNA (their task_struct) using two heuristic traps:

Trap 1 (Privilege Escalation): We check the user's nametag (current_uid().val). If a normal user suddenly tries to execute a command as Root (UID 0), the trap flags it as potential privilege escalation.

Trap 2 (DKOM / The Ghost Check): Advanced rootkits use DKOM (Direct Kernel Object Manipulation) to unlink themselves from the kernel's official process list, turning invisible to commands like ps or top. Our trap checks the exact CPU state. If a program is using the CPU but is not on the kernel's official guest list (for_each_process), we know we have caught a hidden ghost.

3. Self-Defense (Burn the Ships)
If a hacker gets root access, the first thing they will do is type lsmod to find security tools and rmmod to delete them.

The Analogy: To survive, our module cuts its own security camera wires. When the module loads, it uses list_del(&THIS_MODULE->list) to literally sever its connection to the kernel's module registry. It becomes completely invisible to the operating system. You cannot uninstall it; it is permanently fused to the RAM until a hard reboot.

4. The Covert Pipeline (Netlink Sockets)
Standard security tools write their alerts to a text file (like dmesg or syslog). Rootkits instantly delete these files to cover their tracks.

The Analogy: Instead of leaving a paper trail, we build a secure, underground pneumatic tube (a Netlink Socket). When an alert fires, we pack the data into a cardboard shipping box (sk_buff), slap a Netlink header on it, and fire it directly into memory for a User-Space dashboard to catch. No hard drives are touched.


Prerequisites
To compile and run this module, you need a Linux environment (Ubuntu recommended) with root access and kernel compilation headers.
sudo apt-get update
sudo apt-get install build-essential linux-headers-$(uname -r)

Deployment & Testing
Because this module utilizes Ring-0 Self-Defense, loading it is a one-way trip. Once loaded, it cannot be unloaded without rebooting the machine. Test in a Virtual Machine.

Step 1: Compile the Module
In the root directory of the project, run:
make
This invokes the Linux kernel build system to compile smart_meter.c into a raw kernel object (smart_meter.ko).

Step 2: Inject the Module
Insert the compiled module into the running kernel:
sudo insmod smart_meter.ko

Step 3: Verify Invisibility (Self-Defense Check)
Check if the system can see the module:
lsmod | grep smart_meter
Result: Absolute silence. The module has successfully unlinked itself.

Attempt to delete the module:
sudo rmmod smart_meter
Result: rmmod: ERROR: ... No such file or directory. The system denies the module exists.

Step 4: Trigger the Traps
Since the user-space dashboard is not running, the Netlink socket will elegantly fallback to printing backup alerts to the kernel ring buffer (dmesg).

Trigger Trap 1 (Privilege Escalation):
Run any standard command as root.
sudo ls

Trigger Trap 2 (DKOM / Ghost Simulator):
We programmed a deliberate blind spot for any program named ninja to simulate a process unlinked from the for_each_process list.
cp /bin/ls ~/ninja
./ninja

Step 5: Read the Telemetry
Check the kernel logs to see your invisible tripwire in action:
sudo dmesg | tail -n 10

Expected Output:
[!!!] ROOTKIT DETECTOR: ROOT PRIVILEGE EXECUTION CAUGHT: PID [1234] running [sudo]
[!!!] ROOTKIT DETECTOR: GHOST PROCESS CAUGHT: PID [1235] [ninja] is hiding from the task list!

Walkthrough:
If you are reading the smart_meter.c source code, here are the key kernel functions you will encounter:

register_kprobe(): The function that physically attaches our custom C code to the kernel's execution pathway.

current: A magical kernel pointer that always reveals exactly who is using the CPU at this exact nanosecond.

for_each_process(): A built-in kernel macro that acts as a for loop, iterating through the doubly-linked list of every visible program on the computer.

netlink_kernel_create(): Establishes the kernel half of our secure networking pipe.

nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL): Allocates a perfectly sized, cache-friendly block of RAM to hold our alert data before sending it over the network.
