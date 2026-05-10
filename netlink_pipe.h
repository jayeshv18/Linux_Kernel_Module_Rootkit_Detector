#ifndef NETLINK_PIPE_H
#define NETLINK_PIPE_H

#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/epoll.h>

// The exact same channel we mapped in Ring-0
#define NETLINK_USERSOCK 2

// The maximum number of events epoll will pull from the kernel at once
#define MAX_EVENTS 64

// We need a large buffer to catch the kernel firehose (8MB)
#define RCV_BUFFER_SIZE (8 * 1024 * 1024)

//Function Prototypes
/* * 1. Open the Socket
 * Opens the AF_NETLINK socket and expands the OS receive buffer.
 * Returns the Socket File Descriptor (an integer ID), or -1 on failure.
 */
int init_netlink_socket(void);

/* * 2. The Knock
 * Crafts the 16-byte nlmsghdr and sends our PID to the Kernel.
 */
int send_knock(int sock_fd);

/* * 3. The Traffic Controller
 * Initializes the epoll instance and attaches our Netlink socket to it.
 * Returns the epoll File Descriptor.
 */
int setup_epoll(int sock_fd);

#endif // NETLINK_PIPE_H