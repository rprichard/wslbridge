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

void fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fatalv(fmt, ap);
    va_end(ap);
}

void fatalv(const char *fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
    fflush(stdout);
    fflush(stderr);
    // Avoid calling exit, which would call global destructors and destruct the
    // global WakeupFd object.
    _exit(1);
}

void fatalPerror(const char *msg) {
    perror(msg);
    fflush(stdout);
    fflush(stderr);
    // Avoid calling exit, which would call global destructors and destruct the
    // global WakeupFd object.
    _exit(1);
}

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

bool readAllRestarting(int fd, void *buf, size_t count) {
    while (count > 0) {
        ssize_t amt = readRestarting(fd, buf, count);
        if (amt <= 0) {
            return false;
        }
        assert(static_cast<size_t>(amt) <= count);
        buf = reinterpret_cast<char*>(buf) + amt;
        count -= amt;
    }
    return true;
}

void setSocketNoDelay(int s) {
    const int flag = 1;
    const int nodelayRet = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    assert(nodelayRet == 0);
}

BridgedErrno bridgedErrno(int err) {
    switch (err) {
        case 0:                 return BridgedErrno::Success;
        case E2BIG:             return BridgedErrno::bE2BIG;
        case EACCES:            return BridgedErrno::bEACCES;
        case EAGAIN:            return BridgedErrno::bEAGAIN;
        case EFAULT:            return BridgedErrno::bEFAULT;
        case EINVAL:            return BridgedErrno::bEINVAL;
        case EIO:               return BridgedErrno::bEIO;
        case EISDIR:            return BridgedErrno::bEISDIR;
        case ELIBBAD:           return BridgedErrno::bELIBBAD;
        case ELOOP:             return BridgedErrno::bELOOP;
        case EMFILE:            return BridgedErrno::bEMFILE;
        case ENAMETOOLONG:      return BridgedErrno::bENAMETOOLONG;
        case ENFILE:            return BridgedErrno::bENFILE;
        case ENOENT:            return BridgedErrno::bENOENT;
        case ENOEXEC:           return BridgedErrno::bENOEXEC;
        case ENOMEM:            return BridgedErrno::bENOMEM;
        case ENOTDIR:           return BridgedErrno::bENOTDIR;
        case EPERM:             return BridgedErrno::bEPERM;
        case ETXTBSY:           return BridgedErrno::bETXTBSY;
        default:                return BridgedErrno::Unknown;
    }
}

BridgedError bridgedError(int err) {
    return BridgedError { err, bridgedErrno(err) };
}

std::string errorString(BridgedError err) {
    int bridgedErrno = 0;
    switch (err.bridged) {
        case BridgedErrno::Success:             bridgedErrno = 0;                   break;
        case BridgedErrno::bE2BIG:              bridgedErrno = E2BIG;               break;
        case BridgedErrno::bEACCES:             bridgedErrno = EACCES;              break;
        case BridgedErrno::bEAGAIN:             bridgedErrno = EAGAIN;              break;
        case BridgedErrno::bEFAULT:             bridgedErrno = EFAULT;              break;
        case BridgedErrno::bEINVAL:             bridgedErrno = EINVAL;              break;
        case BridgedErrno::bEIO:                bridgedErrno = EIO;                 break;
        case BridgedErrno::bEISDIR:             bridgedErrno = EISDIR;              break;
        case BridgedErrno::bELIBBAD:            bridgedErrno = ELIBBAD;             break;
        case BridgedErrno::bELOOP:              bridgedErrno = ELOOP;               break;
        case BridgedErrno::bEMFILE:             bridgedErrno = EMFILE;              break;
        case BridgedErrno::bENAMETOOLONG:       bridgedErrno = ENAMETOOLONG;        break;
        case BridgedErrno::bENFILE:             bridgedErrno = ENFILE;              break;
        case BridgedErrno::bENOENT:             bridgedErrno = ENOENT;              break;
        case BridgedErrno::bENOEXEC:            bridgedErrno = ENOEXEC;             break;
        case BridgedErrno::bENOMEM:             bridgedErrno = ENOMEM;              break;
        case BridgedErrno::bENOTDIR:            bridgedErrno = ENOTDIR;             break;
        case BridgedErrno::bEPERM:              bridgedErrno = EPERM;               break;
        case BridgedErrno::bETXTBSY:            bridgedErrno = ETXTBSY;             break;
        default:
            return "WSL error #" + std::to_string(err.actual);
    }
    char buf[512];
    char *errStr = strerror_r(bridgedErrno, buf, sizeof(buf));
    assert(errStr != nullptr);
    return errStr;
}

WakeupFd::WakeupFd() {
    if (pipe2(fds_, O_NONBLOCK | O_CLOEXEC) != 0) {
        fatalPerror("error: pipe2 failed");
    }
    FD_ZERO(&fdset_);
}

void WakeupFd::wait() {
    do {
        FD_SET(readFd(), &fdset_);
        const int selectRet = select(readFd() + 1, &fdset_, nullptr, nullptr, nullptr);
        if (selectRet < 0 && errno == EINTR) {
            // Try again.
            continue;
        } else if (selectRet < 0) {
            fatalPerror("internal error: select on wakeup pipe failed");
        }
        std::array<char, 32> dummy;
        const ssize_t readRet = readRestarting(readFd(), dummy.data(), dummy.size());
        if (readRet < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // I'm not sure whether this can happen.
            continue;
        } else if (readRet <= 0) {
            fatalPerror("internal error: wakeup pipe read failed");
        }
    } while (false);
}
