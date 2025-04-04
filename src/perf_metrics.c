#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

// Define performance metrics structure
typedef struct
{
    char operation[64];        // Operation name
    double duration_ms;        // Duration in milliseconds
    size_t data_size;          // Size of data processed (if applicable)
    char additional_info[128]; // Any additional information
} PerfMetric;

// File pointer for logging
static FILE *perf_log_file = NULL;
static int csv_header_written = 0;
static int nanospin_calibrated = 0;

// Initialize performance logging
int init_perf_logging(const char *filename)
{
    perf_log_file = fopen(filename, "w");
    if (!perf_log_file)
    {
        perror("Failed to open performance log file");
        return -1;
    }

    // Write CSV header
    fprintf(perf_log_file, "timestamp,operation,duration_ms,data_size,additional_info\n");
    csv_header_written = 1;

// Calibrate nanospin if available (QNX-specific)
#if defined(__EXT_QNX)
    if (!nanospin_calibrated)
    {
        nanospin_calibrate(0); // Enable and calibrate nanospin
        nanospin_calibrated = 1;
        printf("[INFO] Nanospin calibrated for QNX high-precision timing\n");
    }
#endif

    return 0;
}

// Close performance logging
void close_perf_logging()
{
    if (perf_log_file)
    {
        fclose(perf_log_file);
        perf_log_file = NULL;
    }
}

// Start timing an operation - returns a timespec with the current time
struct timespec start_timing()
{
    struct timespec start_time;

    // Use QNX's CLOCK_MONOTONIC which is high resolution
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Print the raw start time for debugging
    printf("[TIMING DEBUG] Start time: %ld.%09ld\n",
           (long)start_time.tv_sec, (long)start_time.tv_nsec);

    return start_time;
}

// End timing and log the operation
void end_timing(struct timespec start_time, const char *operation, size_t data_size, const char *additional_info)
{
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    // Print the raw end time for debugging
    printf("[TIMING DEBUG] End time: %ld.%09ld\n",
           (long)end_time.tv_sec, (long)end_time.tv_nsec);

    // Print raw timespec values for debugging
    printf("[DEBUG] %s: start_time: %ld.%09ld, end_time: %ld.%09ld\n",
           operation,
           (long)start_time.tv_sec, (long)start_time.tv_nsec,
           (long)end_time.tv_sec, (long)end_time.tv_nsec);

// QNX utility function to convert timespec to nanoseconds and calculate difference
#if defined(__EXT_QNX)
    _Uint64t start_ns = timespec2nsec(&start_time);
    _Uint64t end_ns = timespec2nsec(&end_time);
    _Uint64t duration_ns = end_ns - start_ns;
#else
    // Standard calculation if QNX-specific functions not available
    long duration_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000L +
                       (end_time.tv_nsec - start_time.tv_nsec);
#endif

    // Convert to milliseconds for storage
    double duration_ms = duration_ns / 1000000.0;

    // Get current timestamp
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Log to file if available - always use ms for consistency
    if (perf_log_file)
    {
        fprintf(perf_log_file, "%s,\"%s\",%g,%zu,\"%s\"\n",
                timestamp, operation, duration_ms, data_size, additional_info ? additional_info : "");
        fflush(perf_log_file); // Ensure data is written immediately
    }

    // For console, choose appropriate unit - ms or μs
    if (duration_ms < 0.1)
    {
        // Display in microseconds if less than 0.1ms
        double duration_us = duration_ns / 1000.0;
        printf("[PERF] %s: %g μs (Data size: %zu bytes)\n", operation, duration_us, data_size);
    }
    else
    {
        printf("[PERF] %s: %g ms (Data size: %zu bytes)\n", operation, duration_ms, data_size);
    }
}

// Log throughput metrics
void log_throughput(const char *operation, int message_count, double total_time_ms, size_t total_bytes)
{
    double messages_per_second = message_count / (total_time_ms / 1000.0);
    double mbps = (total_bytes * 8.0 / 1000000.0) / (total_time_ms / 1000.0);

    char info[128];
    snprintf(info, sizeof(info), "msgs/sec: %g, Mbps: %g", messages_per_second, mbps);

    // Get current timestamp
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Log to file
    if (perf_log_file)
    {
        fprintf(perf_log_file, "%s,\"%s\",%g,%zu,\"%s\"\n",
                timestamp, operation, total_time_ms, total_bytes, info);
        fflush(perf_log_file);
    }

    // Print to console with additional debug info for script parsing
    printf("[THROUGHPUT] %s: %g msgs/sec, %g Mbps\n", operation, messages_per_second, mbps);
    printf("DEBUG: total_time_ms=%g total_bytes=%zu\n", total_time_ms, total_bytes);
}
