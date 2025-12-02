#ifndef SFX_UTIL_H
#define SFX_UTIL_H

#include <string.h>
#include <fcntl.h>

#ifdef DEBUG_BUILD
#define dprint fprintf
#else
#define dprint
#endif

void get_filename_no_ext(const char *path, char *output, size_t out_size) {
    if (!path || !output || out_size == 0) {
        if (out_size > 0) output[0] = '\0';
        return;
    }
    const char *filename = strrchr(path, '/');
    const char *filename2 = strrchr(path, '\\');
    if (filename2 && (!filename || filename2 > filename)) {
        filename = filename2;
    }
    filename = filename ? filename + 1 : path;
    strncpy(output, filename, out_size - 1);
    output[out_size - 1] = '\0';
    char *dot = strrchr(output, '.');
    if (dot) {
        *dot = '\0';
    }
}

void write_to_file(const char * filename, const void * src, const uint64_t sz) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("[ERROR] open");
    }
    ssize_t bytes_written = write(fd, src, sz);
    if (bytes_written < 0) {
        perror("[ERROR] write");
        close(fd);
    }
    close(fd);
}

#endif