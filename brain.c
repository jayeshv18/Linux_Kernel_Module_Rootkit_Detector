#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "netlink_pipe.h"
#include "anomaly_math.h"

int main(void) {
    // 1. Initialize the custom math memory banks
    init_math_engine();

    // 2. Open the Netlink pipe with the 8MB shock absorber
    int sock_fd = init_netlink_socket();
    if (sock_fd < 0) exit(EXIT_FAILURE);

    // 3. Attach the epoll traffic controller
    int epoll_fd = setup_epoll(sock_fd);
    if (epoll_fd < 0) exit(EXIT_FAILURE);

    // 4. Introduce ourselves to the Ring-0 kernel module
    if (send_knock(sock_fd) < 0) exit(EXIT_FAILURE);

    printf("\033[1;32m[*] Pure C Split-Brain Architecture Online. PID: %d\033[0m\n", getpid());
    printf("[*] Epoll active. Gathering OS baseline noise for %d events...\n\n", CALIBRATION_LIMIT);

    // The event array where epoll will drop incoming packet notifications
    struct epoll_event events[MAX_EVENTS];
    char buffer[65535];

    while (1) {
        // This blocks the CPU safely until the kernel flags that new data has arrived
        int num_ready = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        for (int i = 0; i < num_ready; i++) {
            if (events[i].data.fd == sock_fd) {

                // Drain the socket
                ssize_t len = recvfrom(sock_fd, buffer, sizeof(buffer), 0, NULL, NULL);
                if (len <= 16) continue; // Skip if it's an error or just the C header

                // Strip the 16-byte Netlink header to get the raw payload
                char *payload = buffer + 16;

                // The kernel sends "EVENT_TYPE:process_name"
                // We split the string at the colon
                char *colon_ptr = strchr(payload, ':');
                if (!colon_ptr) continue; // Malformed string, skip it

                *colon_ptr = '\0'; // Replace colon with a null terminator to split the string
                char *event_type = payload;
                char *proc_name = colon_ptr + 1;

                // TRAP 2: THE DKOM GHOST
                if (strcmp(event_type, "GHOST_EXEC") == 0) {
                    printf("\033[1;31m[CRITICAL ALERT] DKOM GHOST DETECTED: '%s'\033[0m\n", proc_name);
                    continue; // Skip the math engine, scream instantly
                }

                // TRAP 1: PRIVILEGE ESCALATION
                // Feed the process name into our custom math engine
                record_event(proc_name);

                // Ask the math engine to judge the Z-Score
                if (is_anomalous(proc_name)) {
                     printf("\033[1;33m[ANOMALY ALERT] High-deviation root behavior detected: '%s'\033[0m\n", proc_name);
                }
            }
        }
    }

    // Cleanup (Though we technically never reach here unless we catch a SIGINT)
    close(sock_fd);
    close(epoll_fd);
    return 0;
}