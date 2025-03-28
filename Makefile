# Makefile for RSA key exchange program

# Compiler and flags
CC = qcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto -lsocket

# Directories
BUILD_DIR = build
BIN_DIR = bin

# Object files
OBJ_SENDER = $(BUILD_DIR)/sender.o
OBJ_RECEIVER = $(BUILD_DIR)/receiver.o
TARGET_SENDER = $(BIN_DIR)/sender
TARGET_RECEIVER = $(BIN_DIR)/receiver

# Default target
all: $(TARGET_SENDER) $(TARGET_RECEIVER)

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
.PHONY: all clean receiver sender
