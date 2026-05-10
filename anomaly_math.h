#ifndef ANOMALY_MATH_H
#define ANOMALY_MATH_H

#define CALIBRATION_LIMIT 50
#define MAX_UNIQUE_PROCESSES 1024
#define Z_SCORE_THRESHOLD 2.5 // 99% confidence interval

// Our custom memory bank to track OS behavior
typedef struct {
    char process_name[256];
    int current_window_count; // How many times it ran in the current 50-event window
    double historical_mean;   // The established normal frequency
    double std_deviation;     // The variance
    int is_calibrated;        // Flag to know if we have enough data to judge it
} ProcessProfile;

// Initialize the memory bank
void init_math_engine(void);

// Record an event and update the math
void record_event(const char *process_name);

// mathematically judge if an event is anomalous
int is_anomalous(const char *process_name);

#endif // ANOMALY_MATH_H