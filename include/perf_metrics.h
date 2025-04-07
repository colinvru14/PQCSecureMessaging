#ifndef PERF_METRICS_H
#define PERF_METRICS_H

#include <time.h>
#include <stddef.h>

// Initialize performance logging
int init_perf_logging(const char *filename);

// Close performance logging
void close_perf_logging();

// Start timing an operation
struct timespec start_timing();

// End timing and log the operation
void end_timing(struct timespec start_time, const char *operation, size_t data_size, const char *additional_info);

// Log throughput metrics
void log_throughput(const char *operation, int message_count, double total_time_ms, size_t total_bytes);

#endif /* PERF_METRICS_H */
