#include "SocketIo.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>

#include <algorithm>
#include <array>

ssize_t writeRestarting(int fd, const void *buf, size_t count) {
    ssize_t ret = 0;
    do {
        ret = write(fd, buf, count);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

bool writeAllRestarting(int fd, const void *buf, size_t count) {
    while (count > 0) {
        ssize_t amt = writeRestarting(fd, buf, count);
        if (amt <= 0) {
            return false;
        }
        assert(static_cast<size_t>(amt) <= count);
        buf = reinterpret_cast<const char*>(buf) + amt;
        count -= amt;
    }
    return true;
}

ssize_t readRestarting(int fd, void *buf, size_t count) {
    ssize_t ret = 0;
    do {
        ret = read(fd, buf, count);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

void setSocketNoDelay(int s) {
    const int flag = 1;
    const int nodelayRet = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    assert(nodelayRet == 0);
}

WakeupFd::WakeupFd() {
    int iResult = pipe2(fds_, O_NONBLOCK);
    if (iResult != 0) {
        perror("pipe2 failed");
        exit(1);
    }
    FD_ZERO(&fdset_);
}

void WakeupFd::wait() {
    do {
        FD_SET(readFd(), &fdset_);
        int ret = select(readFd() + 1, &fdset_, nullptr, nullptr, nullptr);
        if (ret < 0 && ret == EINTR) {
            // Try again.
            continue;
        } else if (ret < 0) {
            perror("internal error: select on wakeup pipe failed");
            exit(1);
        }
        std::array<char, 32> dummy;
        if (readRestarting(readFd(), dummy.data(), dummy.size()) <= 0) {
            fprintf(stderr, "internal error: wakeup pipe read failed\n");
            exit(1);
        }
    } while (false);
}
