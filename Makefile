DEBUG = -g
CC = qcc
LD = qcc

TARGET = -Vgcc_ntox86_64
#TARGET = -Vgcc_ntoaarch64le  # Comment out or switch as needed

# Include directories
INCDIR = include
COMMONDIR = common
CFLAGS += $(DEBUG) $(TARGET) -Wall -I$(INCDIR) -I$(COMMONDIR)

# Library directory and linking flags
LIBDIR = lib/x86_64
COMMON_OBJS = common/randombytes.o common/sha2.o common/aes.o common/fips202.o common/sp800-185.o
LDFLAGS += $(DEBUG) $(TARGET) -L$(LIBDIR) -lml-kem-512_clean -lml-dsa-44_clean

BINS = PQCMessaging

all: $(BINS)

# Compile common objects
common/randombytes.o: common/randombytes.c common/randombytes.h
	$(CC) $(CFLAGS) -c common/randombytes.c -o common/randombytes.o

common/sha2.o: common/sha2.c common/sha2.h
	$(CC) $(CFLAGS) -c common/sha2.c -o common/sha2.o

common/aes.o: common/aes.c common/aes.h
	$(CC) $(CFLAGS) -c common/aes.c -o common/aes.o

common/fips202.o: common/fips202.c common/fips202.h
	$(CC) $(CFLAGS) -c common/fips202.c -o common/fips202.o

common/sp800-185.o: common/sp800-185.c common/sp800-185.h
	$(CC) $(CFLAGS) -c common/sp800-185.c -o common/sp800-185.o

PQCMessaging: src/PQCMessaging.c $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o build/PQCMessaging src/PQCMessaging.c $(COMMON_OBJS) $(LDFLAGS)

clean:
	rm -rf build/$(BINS) build/*.o

.PHONY: all clean