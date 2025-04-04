# Makefile for RSA key exchange program

# Compiler and flags
CC = qcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto -lsocket

# ------- START OF VARIABLES TO CHANGE FOR EITHER X86_64 OR AARCH64 BINARIES ----------
TARGET = -Vgcc_ntox86_64
#TARGET = -Vgcc_ntoaarch64le

LIBDIR = lib/x86_64
#LIBDIR = lib/aarch64
# ------- END OF VARIABLES TO CHANGE FOR EITHER X86_64 OR AARCH64 BINARIES ----------

# Directories
BUILD_DIR = build
BIN_DIR = bin
INCDIR = include
COMMONDIR = common

CFLAGS += $(TARGET) -I$(INCDIR) -I$(COMMONDIR)
PQC_LDFLAGS = -lml-kem-512_clean -lml-dsa-44_clean
LDFLAGS += $(TARGET) -L$(LIBDIR) $(PQC_LDFLAGS)

# Object files
OBJ_SENDER = $(BUILD_DIR)/sender.o
OBJ_RECEIVER = $(BUILD_DIR)/receiver.o
TARGET_SENDER = $(BIN_DIR)/sender
TARGET_RECEIVER = $(BIN_DIR)/receiver

# Object files for PQC targets
COMMON_OBJS = $(BUILD_DIR)/randombytes.o $(BUILD_DIR)/sha2.o $(BUILD_DIR)/aes.o $(BUILD_DIR)/fips202.o $(BUILD_DIR)/sp800-185.o
OBJ_PQC_SENDER = $(BUILD_DIR)/pqc_sender.o
OBJ_PQC_RECEIVER = $(BUILD_DIR)/pqc_receiver.o
TARGET_PQC_SENDER = $(BIN_DIR)/pqc_sender
TARGET_PQC_RECEIVER = $(BIN_DIR)/pqc_receiver

# Performance test objects and targets
OBJ_PQC_PERF_TEST = $(BUILD_DIR)/pqc_perf_test.o
TARGET_PQC_PERF_TEST = $(BIN_DIR)/pqc_perf_test

OBJ_TRADITIONAL_PERF_TEST = $(BUILD_DIR)/traditional_perf_test.o
TARGET_TRADITIONAL_PERF_TEST = $(BIN_DIR)/traditional_perf_test

# Performance metrics objects
OBJ_PERF_METRICS = $(BUILD_DIR)/perf_metrics.o

# Default target
all: $(TARGET_SENDER) $(TARGET_RECEIVER) $(TARGET_PQC_SENDER) $(TARGET_PQC_RECEIVER) $(TARGET_PQC_PERF_TEST) $(TARGET_TRADITIONAL_PERF_TEST)

# Create directories if they don't exist
$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

# Compile source for sender and receiver
$(OBJ_SENDER): src/traditional/sender.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DSENDER -c $< -o $@

$(OBJ_RECEIVER): src/traditional/receiver.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRECEIVER -c $< -o $@

# Link object files to create sender and receiver executables
$(TARGET_SENDER): $(OBJ_SENDER) | $(BIN_DIR)
	$(CC) $(OBJ_SENDER) $(LDFLAGS) -o $@

$(TARGET_RECEIVER): $(OBJ_RECEIVER) | $(BIN_DIR)
	$(CC) $(OBJ_RECEIVER) $(LDFLAGS) -o $@

# Compile common PQC objects
$(BUILD_DIR)/randombytes.o: $(COMMONDIR)/randombytes.c $(COMMONDIR)/randombytes.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/sha2.o: $(COMMONDIR)/sha2.c $(COMMONDIR)/sha2.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/aes.o: $(COMMONDIR)/aes.c $(COMMONDIR)/aes.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/fips202.o: $(COMMONDIR)/fips202.c $(COMMONDIR)/fips202.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/sp800-185.o: $(COMMONDIR)/sp800-185.c $(COMMONDIR)/sp800-185.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile source for PQC sender and receiver
$(OBJ_PQC_SENDER): src/pqc/pqc_sender.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_PQC_RECEIVER): src/pqc/pqc_receiver.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile source for performance tests
$(OBJ_PQC_PERF_TEST): src/pqc_perf_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_TRADITIONAL_PERF_TEST): src/traditional_perf_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile performance metrics source
$(OBJ_PERF_METRICS): src/perf_metrics.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files to create PQC sender and receiver executables
$(TARGET_PQC_SENDER): $(OBJ_PQC_SENDER) $(COMMON_OBJS) $(OBJ_PERF_METRICS) | $(BIN_DIR)
	$(CC) $(OBJ_PQC_SENDER) $(COMMON_OBJS) $(OBJ_PERF_METRICS) $(LDFLAGS) -o $@

$(TARGET_PQC_RECEIVER): $(OBJ_PQC_RECEIVER) $(COMMON_OBJS) $(OBJ_PERF_METRICS) | $(BIN_DIR)
	$(CC) $(OBJ_PQC_RECEIVER) $(COMMON_OBJS) $(OBJ_PERF_METRICS) $(LDFLAGS) -o $@

# Link object files to create performance test executables
$(TARGET_PQC_PERF_TEST): $(OBJ_PQC_PERF_TEST) $(COMMON_OBJS) $(OBJ_PERF_METRICS) | $(BIN_DIR)
	$(CC) $(OBJ_PQC_PERF_TEST) $(COMMON_OBJS) $(OBJ_PERF_METRICS) $(LDFLAGS) -o $@

$(TARGET_TRADITIONAL_PERF_TEST): $(OBJ_TRADITIONAL_PERF_TEST) | $(BIN_DIR)
	$(CC) $(OBJ_TRADITIONAL_PERF_TEST) $(LDFLAGS) -o $@

# Run as receiver
receiver: $(TARGET_RECEIVER)
	./$(TARGET_RECEIVER)

# Run as sender
sender: $(TARGET_SENDER)
	./$(TARGET_SENDER)

# Run as PQC receiver
pqc_receiver: $(TARGET_PQC_RECEIVER)
	./$(TARGET_PQC_RECEIVER)

# Run as PQC sender
pqc_sender: $(TARGET_PQC_SENDER)
	./$(TARGET_PQC_SENDER)

# Run the performance tests
pqc_perf_test: $(TARGET_PQC_PERF_TEST)
	./$(TARGET_PQC_PERF_TEST)

traditional_perf_test: $(TARGET_TRADITIONAL_PERF_TEST)
	./$(TARGET_TRADITIONAL_PERF_TEST)

# Clean build files
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Phony targets
.PHONY: all clean receiver sender pqc_receiver pqc_sender pqc_perf_test traditional_perf_test
