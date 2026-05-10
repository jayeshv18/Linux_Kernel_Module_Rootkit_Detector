#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "netlink_pipe.h"

// 1. OPEN THE RAW SOCKET & EXPAND THE BUFFER
int init_netlink_socket(void) {
    // Open the raw Netlink pipe to talk to our Ring-0 module
    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock_fd < 0) {
        perror("[-] FATAL: Failed to open Netlink socket (Are you root?)");
        return -1;
    }

    // The default Linux socket buffer is tiny (~200KB).
    // We force the OS to give us an 8MB receive buffer to handle Ring-0 traffic bursts.
    int rcv_buffer_size = RCV_BUFFER_SIZE;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &rcv_buffer_size, sizeof(rcv_buffer_size)) < 0) {
        perror("[-] WARNING: Failed to expand receive buffer");
        // We don't return -1 here; we can still try to run on the smaller buffer.
    }
    // Bind the socket to our process ID
    struct sockaddr_nl src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // Our unique Ring-3 ID
    src_addr.nl_groups = 0;     // Unicast only

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("[-] FATAL: Failed to bind socket");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}
// 2. FIRE THE KNOCK TO RING-0

int send_knock(int sock_fd) {
    struct sockaddr_nl dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   // PID 0 always means "The Linux Kernel"
    dest_addr.nl_groups = 0;

    // We have to build the 16-byte Netlink Header manually in memory
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(1024));
    if (!nlh) return -1;

    memset(nlh, 0, NLMSG_SPACE(1024));
    nlh->nlmsg_len = NLMSG_SPACE(1024);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    // The Payload
    strcpy(NLMSG_DATA(nlh), "KNOCK");

    // Fire it down the pipe
    int res = sendto(sock_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    free(nlh);

    if (res < 0) {
        perror("[-] FATAL: Failed to send Knock to Kernel");
        return -1;
    }
    return 0;
}

// 3. SET UP EPOLL (THE HIGH-SPEED TRAFFIC CONTROLLER)
int setup_epoll(int sock_fd) {
    // Ask the kernel to create a new epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[-] FATAL: Failed to create epoll instance");
        return -1;
    }

    // Configure what we want epoll to watch for
    struct epoll_event event;
    event.events = EPOLLIN; // We only care when new data comes IN from the kernel
    event.data.fd = sock_fd;

    // Attach our Netlink socket to the epoll traffic controller
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &event) < 0) {
        perror("[-] FATAL: Failed to add socket to epoll");
        close(epoll_fd);
        return -1;
    }

    return epoll_fd;
}