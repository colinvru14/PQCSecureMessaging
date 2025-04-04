#include "randombytes.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

int randombytes(uint8_t *output, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;  // Error opening /dev/urandom
    }
    ssize_t bytes_read = read(fd, output, n);
    close(fd);
    if (bytes_read != (ssize_t)n) {
        return -1;  // Failed to read enough bytes
    }
    return 0;  // Success
}
