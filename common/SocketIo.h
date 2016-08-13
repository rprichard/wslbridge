#pragma once

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <utility>
#include <vector>

const size_t kBackendToFrontendWindow = 4096;
const size_t kFrontendToBackendWindow = 4096;

class IoChannel {
public:
    IoChannel(int readFd, int writeFd) : readFd_(readFd), writeFd_(writeFd), buffer_(4096)
    {
    }

    void prepareForSelect(int &maxfd, fd_set *readfds, fd_set *writefds);
    void serviceIo(const fd_set *readfds, const fd_set *writefds);
    bool isBufferFull() const { return count_ == buffer_.size(); }
    bool isBufferEmpty() const { return count_ == 0; }
    bool hasReadFailed() const { return readFailed_; }
    bool hasWriteFailed() const { return writeFailed_; }
    bool hasFailed() const { return readFailed_ || writeFailed_; }

    void setWindow(size_t amount) { outputWindow_ = amount; }
    void increaseWindow(size_t amount) {
        assert(outputWindow_ != SIZE_MAX);
        outputWindow_ += amount;
    }
    size_t bytesWritten() { return bytesWritten_; }
    void resetBytesWritten() { bytesWritten_ = 0; }

private:
    int readFd_;
    int writeFd_;
    size_t count_ = 0;
    size_t outputWindow_ = SIZE_MAX;
    size_t bytesWritten_ = 0;
    std::vector<char> buffer_;
    bool readFailed_ = false;
    bool writeFailed_ = false;
};

class ControlSocket {
public:
    ControlSocket(int fd) : fd_(fd) {}

    void write(void *data, size_t amt) {
        char *cp = reinterpret_cast<char*>(data);
        outBuffer_.insert(outBuffer_.end(), cp, cp + amt);
    }

    size_t size() { return inBuffer_.size(); }

    void read(void *data, size_t amt) {
        assert(amt <= inBuffer_.size());
        memcpy(data, &inBuffer_[0], amt);
        memmove(&inBuffer_[0], &inBuffer_[amt], inBuffer_.size() - amt);
        inBuffer_.resize(inBuffer_.size() - amt);
    }

    void prepareForSelect(int &maxfd, fd_set *readfds, fd_set *writefds);
    void serviceIo(const fd_set *readfds, const fd_set *writefds);
    bool hasFailed() const { return readFailed_ || writeFailed_; }

private:
    int fd_;
    std::vector<char> outBuffer_;
    std::vector<char> inBuffer_;
    bool readFailed_ = false;
    bool writeFailed_ = false;
};

ssize_t writeRestarting(int fd, const void *buf, size_t count);
ssize_t readRestarting(int fd, void *buf, size_t count);
void setSocketNonblocking(int s);
void setSocketNoDelay(int s);

typedef std::pair<uint16_t, uint16_t> TermSize;

struct Packet {
    enum class Type { SetSize, IncreaseWindow, ChildExitStatus } type;
    union {
        TermSize size;
        int32_t amount;
        int32_t exitStatus;
    } u;
};

class WakeupFd {
public:
    WakeupFd();
    ~WakeupFd() {
        close(fds_[0]);
        close(fds_[1]);
    }

    void set() {
        char dummy = 0;
        writeRestarting(fds_[1], &dummy, 1);
    }

    void clear() {
        char dummy[128];
        readRestarting(fds_[0], dummy, sizeof(dummy));
    }

    int readFd() const { return fds_[0]; }

private:
    int fds_[2];
};
