#ifndef TIMING_H
#define TIMING_H

#include <chrono>
typedef std::chrono::system_clock Clock;

#ifdef TPM_POSIX
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <cstdio>
#elif TPM_WINDOWS
#include <fstream>
#endif

static void writeTiming(const char* caller, double timingValue) {
    printf("Time [ %s ]: %f ms\n", caller, timingValue);
    #ifdef TPM_POSIX
    int fd = open(caller, O_WRONLY | O_CREAT | O_APPEND, 0600);
    char buf[2048];
    snprintf(buf, sizeof(buf), "%f\n", timingValue);
    write(fd, buf, strlen(buf));
    close(fd);
#elif TPM_WINDOWS
    std::ofstream outfile;
    outfile.open(caller, std::ios_base::app);
    outfile << timingValue << "\n";
#endif
}

#endif