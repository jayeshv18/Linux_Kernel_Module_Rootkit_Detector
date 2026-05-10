
obj-m += smart_meter.o

# Force GCC-12 to satisfy the Linux Kernel 6.8 security flags
CC = gcc-12
CFLAGS = -Wall -O3
LDFLAGS = -lm

TARGET = brain
SRCS = brain.c netlink_pipe.c anomaly_math.c
OBJS = $(SRCS:.c=.o)

# By default, typing 'make' will build both components
all: kernel_module user_space_agent

# Build the Ring-0 Kernel Module (Passing GCC-12 explicitly)
kernel_module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) CC=$(CC) modules

# Build the Ring-3 User-Space Agent
user_space_agent: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compile individual C files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up both Kernel and User-Space compiled files
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
	rm -f $(OBJS) $(TARGET)