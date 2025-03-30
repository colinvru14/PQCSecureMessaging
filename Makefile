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

# Default target
all: $(TARGET_SENDER) $(TARGET_RECEIVER) $(TARGET_PQC_SENDER) $(TARGET_PQC_RECEIVER)

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
	
# Link object files to create PQC sender and receiver executables
$(TARGET_PQC_SENDER): $(OBJ_PQC_SENDER) $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(OBJ_PQC_SENDER) $(COMMON_OBJS) $(LDFLAGS) -o $@

$(TARGET_PQC_RECEIVER): $(OBJ_PQC_RECEIVER) $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(OBJ_PQC_RECEIVER) $(COMMON_OBJS) $(LDFLAGS) -o $@

# Run as receiver
receiver: $(TARGET_RECEIVER)
	./$(TARGET_RECEIVER)

# Run as sender
sender: $(TARGET_SENDER)
	./$(TARGET_SENDER)

# Clean build files
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Phony targets
.PHONY: all clean receiver sender pqc_receiver pqc_sender
