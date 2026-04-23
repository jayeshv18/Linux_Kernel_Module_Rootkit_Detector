import socket   # Required for Netlink pipes
import os       # Required to get our PID
import struct   # Required to pack Python variables into raw C-struct memory bytes

import numpy as np                                # NumPy: A hardcore C-based math engine wrapped in Python.
from sklearn.ensemble import IsolationForest      # SciKit-Learn: The enterprise ML library. Isolation Forest is our anomaly hunting algorithm.
from collections import defaultdict               # A special dictionary that automatically initializes a variable to 0 if it doesn't exist yet (saves us writing extra if/else statements).

NETLINK_USERSOCK = 2      # The kernel Door number we are listening to.
CALIBRATION_LIMIT = 50    # How many background events we need to watch before the AI has enough data to know what "normal" looks like.

def main():

    # OPEN AND BIND THE NETLINK PIPE

    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_USERSOCK)
        my_pid = os.getpid()
        sock.bind((my_pid, 0))
    except PermissionError:
        print("[-] FATAL: You must run the brain as Root (sudo).")
        return


    # CRAFT AND FIRE THE KNOCK

    payload = b"KNOCK\x00"
    msg_len = 16 + len(payload)
    # Pack 16 bytes: length(Int), type(Short), flags(Short), seq(Int), pid(Int)
    header = struct.pack("=IHHII", msg_len, 0, 0, 0, my_pid)
    sock.sendto(header + payload, (0, 0))

    print(f"[*] Split-Brain AI Architecture Online. PID: {my_pid}")
    print(f"[*] Entering Calibration Phase. Gathering OS baseline noise for {CALIBRATION_LIMIT} events...\n")


    # INITIALIZE THE AI MEMORY BANKS

    # This dictionary acts as our database.
    # Key = Program Name (String), Value = How many times it ran (Integer)
    # Example: {"sshd": 150, "cron": 45}
    process_counts = defaultdict(int)

    # The Machine Learning Engine.
    # "contamination=0.05" tells the AI: "Assume about 5% of the data I feed you is malicious/anomalous."
    # random_state=42 just ensures the math is reproducible if we restart the script.
    model = IsolationForest(contamination=0.05, random_state=42)

    event_count = 0
    is_trained = False # A flag so we know if the AI is ready to hunt


    # THE INFINITE EVENT LOOP

    while True:
        # Block and wait for the kernel to send us an sk_buff
        data, _ = sock.recvfrom(65535)

        # Strip the 16-byte C header, convert to UTF-8, and strip the null terminator
        raw_telemetry = data[16:].decode('utf-8', errors='ignore').strip('\x00')

        # Safety check: If the string doesn't have a colon, it's malformed data. Skip it.
        if ":" not in raw_telemetry:
            continue

        # Split "UID0_EXEC:sshd" into two variables: event_type="UID0_EXEC", proc_name="sshd"
        event_type, proc_name = raw_telemetry.split(":", 1)

        # --- TRAP 2: THE DKOM GHOST (100% Malicious) ---
        # If the kernel sends GHOST_EXEC, we don't need AI. We know for a mathematical fact
        # that the process is hiding from the kernel list. Scream immediately.
        if event_type == "GHOST_EXEC":
            print(f"\033[1;31m[CRITICAL ALERT] DKOM GHOST DETECTED CAUGHT: {proc_name}\033[0m")
            continue

        # TRAP 1: PRIVILEGE ESCALATION (Feed to AI)
        # 1. Add 1 to the tally for this specific program.
        process_counts[proc_name] += 1
        current_freq = process_counts[proc_name] # Store the new total in a variable
        event_count += 1


        # CALIBRATION (The AI is learning)
        if not is_trained:
            print(f" [CALIBRATING] {event_count}/{CALIBRATION_LIMIT} - Logged '{proc_name}' (Seen {current_freq} times)")

            # Have we hit 50 events yet?
            if event_count >= CALIBRATION_LIMIT:
                # The ML algorithm requires a specific memory shape.
                # list(process_counts.values()) gives a flat array: [150, 45, 12]
                # .reshape(-1, 1) converts it into a 2D vertical column matrix:
                # [[150], [45], [12]]. This is the format SciKit-Learn expects.
                X_train = np.array(list(process_counts.values())).reshape(-1, 1)

                # .fit() is the actual Machine Learning process. The CPU does heavy
                # floating-point math to figure out the statistical boundaries of "normal".
                model.fit(X_train)

                is_trained = True # Flip the flag. The weapon is hot.
                print("\n\033[1;32m[*] Calibration Complete. Isolation Forest Model Trained.\033[0m")
                print("\033[1;32m[*] AI Radar is now ACTIVE and hunting for anomalies.\033[0m\n")


        # ACTIVE HUNT (The AI is judging)

        else:
            # We take the current frequency of the program that just ran,
            # pack it into a 2D array, and ask the trained AI to judge it.
            X_test = np.array([[current_freq]])

            # .predict() returns exactly one of two integers:
            #  1 : The AI mathematically believes this is normal background noise.
            # -1 : The AI mathematically believes this is highly anomalous.
            prediction = model.predict(X_test)[0]

            if prediction == -1:
                # If a hacker runs 'ls' or 'cat', its frequency is 1. The AI compares '1'
                # against normal daemons that run 100+ times, isolates it, and flags it.
                print(f"\033[1;33m[AI ALERT] ANOMALOUS ROOT BEHAVIOR DETECTED: '{proc_name}' (Only seen {current_freq} times)\033[0m")
            else:
                print(f" [NORMAL NOISE] {proc_name}")


            # DYNAMIC RE-TRAINING

            # Linux changes over time. Every 50 events (modulo math), we re-feed the updated
            # memory banks into the AI so it learns the "new normal" and gets smarter over time.
            if event_count % CALIBRATION_LIMIT == 0:
                X_train = np.array(list(process_counts.values())).reshape(-1, 1)
                model.fit(X_train)

if __name__ == "__main__":
    main()