#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "anomaly_math.h"

// Our Global Memory Bank
ProcessProfile profiles[MAX_UNIQUE_PROCESSES];
int unique_process_count = 0;
int total_events_in_window = 0;

void init_math_engine(void) {
    memset(profiles, 0, sizeof(profiles));
    unique_process_count = 0;
    total_events_in_window = 0;
}

// Internal function to find a process in our memory bank (Replaces Python Dictionary lookup)
static int find_profile_index(const char *process_name) {
    for (int i = 0; i < unique_process_count; i++) {
        if (strcmp(profiles[i].process_name, process_name) == 0) {
            return i;
        }
    }
    // If not found, create a new one
    if (unique_process_count < MAX_UNIQUE_PROCESSES) {
        strcpy(profiles[unique_process_count].process_name, process_name);
        profiles[unique_process_count].current_window_count = 0;
        unique_process_count++;
        return unique_process_count - 1;
    }
    return -1; // Memory bank full
}

void record_event(const char *process_name) {
    int index = find_profile_index(process_name);
    if (index == -1) return; // Drop if we hit the 1024 unique process limit

    profiles[index].current_window_count++;
    total_events_in_window++;

    // DYNAMIC RETRAINING: Every 50 events, we recalculate the Mean and Standard Deviation
    if (total_events_in_window >= CALIBRATION_LIMIT) {
        for (int i = 0; i < unique_process_count; i++) {
            ProcessProfile *p = &profiles[i];

            // If this is the first time training, set the baseline
            if (!p->is_calibrated) {
                p->historical_mean = p->current_window_count;
                p->std_deviation = 1.0; // Prevent divide-by-zero on first run
                p->is_calibrated = 1;
            } else {
                // Moving average math
                double old_mean = p->historical_mean;
                p->historical_mean = (old_mean + p->current_window_count) / 2.0;

                // Simple variance estimation for high-speed calculation
                double variance = pow((p->current_window_count - p->historical_mean), 2);
                p->std_deviation = sqrt(variance);

                // Absolute minimum deviation to prevent division by zero
                if (p->std_deviation < 0.1) p->std_deviation = 0.1;
            }
            // Reset the counter for the next 50-event window
            p->current_window_count = 0;
        }
        total_events_in_window = 0; // Reset global window
        printf("\033[1;34m[*] AI Math Engine Recalibrated over %d processes.\033[0m\n", unique_process_count);
    }
}

int is_anomalous(const char *process_name) {
    int index = find_profile_index(process_name);
    if (index == -1) return 0; // If memory is full, fail open (safe)

    ProcessProfile *p = &profiles[index];

    if (!p->is_calibrated) {
        return 0; // Don't judge if we haven't established a baseline yet
    }

    // THE Z-SCORE EQUATION
    double z_score = (p->current_window_count - p->historical_mean) / p->std_deviation;

    // If the Z-Score is highly negative (meaning it ran much less than normal)
    // or highly positive (ran way more than normal), it is an anomaly.
    if (fabs(z_score) > Z_SCORE_THRESHOLD) {
        return 1; // ANOMALY CAUGHT
    }

    return 0; // NORMAL BACKGROUND NOISE
}