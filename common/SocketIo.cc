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

namespace {

static inline bool isEAgainOrWouldBlock(int e) {
    return e == EAGAIN || e == EWOULDBLOCK;
}

} // namespace

void IoChannel::prepareForSelect(int &maxfd, fd_set *readfds, fd_set *writefds) {
    if (!writeFailed_ && !isBufferEmpty() && outputWindow_ > 0) {
        maxfd = std::max(maxfd, writeFd_);
        FD_SET(writeFd_, writefds);
    }
    if (!readFailed_ && !isBufferFull()) {
        maxfd = std::max(maxfd, readFd_);
        FD_SET(readFd_, readfds);
    }
}

void IoChannel::serviceIo(const fd_set *readfds, const fd_set *writefds) {
    if (!writeFailed_ && !isBufferEmpty() && outputWindow_ > 0 &&
            FD_ISSET(writeFd_, writefds)) {
        const size_t limit = std::min(count_, outputWindow_);
        const ssize_t actual = writeRestarting(writeFd_, &buffer_[0], limit);
        if (actual == 0 || (actual < 0 && !isEAgainOrWouldBlock(errno))) {
            writeFailed_ = true;
        } else if (actual > 0) {
            assert(static_cast<size_t>(actual) <= limit);
            memmove(&buffer_[0], &buffer_[actual], count_ - actual);
            count_ -= actual;
            if (outputWindow_ != SIZE_MAX) {
                outputWindow_ -= actual;
            }
            bytesWritten_ += actual;
        }
    }
    if (!readFailed_ && !isBufferFull() && FD_ISSET(readFd_, readfds)) {
        const size_t remaining = buffer_.size() - count_;
        ssize_t actual = readRestarting(readFd_, &buffer_[count_], remaining);
        if (actual == 0 || (actual < 0 && !isEAgainOrWouldBlock(errno))) {
            readFailed_ = true;
        } else if (actual > 0) {
            assert(static_cast<size_t>(actual) <= remaining);
            count_ += actual;
        }
    }
    if (writeFailed_) {
        // Discard buffered data.
        count_ = 0;
    }
}

void ControlSocket::prepareForSelect(int &maxfd, fd_set *readfds, fd_set *writefds) {
    if (!writeFailed_ && !outBuffer_.empty()) {
        maxfd = std::max(maxfd, fd_);
        FD_SET(fd_, writefds);
    }
    if (!readFailed_) {
        maxfd = std::max(maxfd, fd_);
        FD_SET(fd_, readfds);
    }
}

void ControlSocket::serviceIo(const fd_set *readfds, const fd_set *writefds) {
    if (!writeFailed_ && !outBuffer_.empty() && FD_ISSET(fd_, writefds)) {
        const ssize_t actual = writeRestarting(fd_, &outBuffer_[0], outBuffer_.size());
        if (actual == 0 || (actual < 0 && !isEAgainOrWouldBlock(errno))) {
            writeFailed_ = true;
        } else if (actual > 0) {
            assert(static_cast<size_t>(actual) <= outBuffer_.size());
            const size_t remaining = outBuffer_.size() - actual;
            memmove(&outBuffer_[0], &outBuffer_[actual], remaining);
            outBuffer_.resize(remaining);
        }
    }
    if (!readFailed_ && FD_ISSET(fd_, readfds)) {
        std::array<char, 4096> buf;
        const size_t actual = readRestarting(fd_, &buf[0], buf.size());
        if (actual == 0 || (actual < 0 && !isEAgainOrWouldBlock(errno))) {
            readFailed_ = true;
        } else if (actual > 0) {
            inBuffer_.insert(inBuffer_.end(), &buf[0], &buf[actual]);
        }
    }
    if (readFailed_ || writeFailed_) {
        outBuffer_.clear();
        inBuffer_.clear();
    }
}

ssize_t writeRestarting(int fd, const void *buf, size_t count) {
    ssize_t ret = 0;
    do {
        ret = write(fd, buf, count);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

ssize_t readRestarting(int fd, void *buf, size_t count) {
    ssize_t ret = 0;
    do {
        ret = read(fd, buf, count);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

void setSocketNonblocking(int s) {
    const int fcntlRet = fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
    assert(fcntlRet == 0);
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
}
