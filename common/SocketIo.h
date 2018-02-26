#pragma once

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <array>
#include <string>
#include <utility>

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

void fatal(const char *fmt, ...)
    __attribute__((noreturn))
    __attribute__((format(printf, 1, 2)));
void fatalv(const char *fmt, va_list ap) __attribute__((noreturn));
void fatalPerror(const char *msg) __attribute__((noreturn));
ssize_t writeRestarting(int fd, const void *buf, size_t count);
bool writeAllRestarting(int fd, const void *buf, size_t count);
ssize_t readRestarting(int fd, void *buf, size_t count);
bool readAllRestarting(int fd, void *buf, size_t count);
void setSocketNoDelay(int s);

struct TermSize {
    uint16_t cols;
    uint16_t rows;

    bool operator==(const TermSize &o) const {
        return cols == o.cols && rows == o.rows;
    }
    bool operator!=(const TermSize &o) const {
        return !(*this == o);
    }
};

struct WindowParams {
    int32_t size;       // Maximum number of bytes in flight.
    int32_t threshold;  // Minimum remaining window to initiate I/O.
};

enum class BridgedErrno : int32_t {
    Success = 0,
    Unknown,
    bE2BIG,
    bEACCES,
    bEAGAIN,
    bEFAULT,
    bEINVAL,
    bEIO,
    bEISDIR,
    bELIBBAD,
    bELOOP,
    bEMFILE,
    bENAMETOOLONG,
    bENFILE,
    bENOENT,
    bENOEXEC,
    bENOMEM,
    bENOTDIR,
    bEPERM,
    bETXTBSY,
};

struct BridgedError {
    int32_t actual;
    BridgedErrno bridged;
};

struct SpawnError {
    enum class Type : int32_t {
        Success = 0,
        ForkPtyFailed,
        ExecFailed,
        ChdirFailed,
    } type;
    BridgedError error;
};

BridgedErrno bridgedErrno(int err);
BridgedError bridgedError(int err);
std::string errorString(BridgedError err);

struct Packet {
    uint32_t size;
    enum class Type : int32_t {
        SetSize,
        IncreaseWindow,
        SpawnFailed,
        ChildExitStatus,
        CloseStdoutPipe
    } type;
    union {
        TermSize termSize;
        struct {
            int32_t amount;
            bool isErrorPipe;
        } window;
        int32_t exitStatus;
        SpawnError spawnError;
    } u;
};

struct PacketSpawnFailed : Packet {
    char exe[1024];
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

    void wait();

private:
    int readFd() const { return fds_[0]; }

    fd_set fdset_;
    int fds_[2];
};

template <typename T, void packetHandlerFunc(T*, const Packet&), void readFailure()>
void readControlSocketThread(int controlSocketFd, T *userObj) {
    union {
        Packet base;
        PacketSpawnFailed spawnFailed;
    } packet = {};
    while (true) {
        if (!readAllRestarting(controlSocketFd, &packet.base,
                               sizeof(packet.base))) {
            readFailure();
        }
        if (packet.base.size < sizeof(Packet) ||
                packet.base.size > sizeof(packet)) {
            readFailure();
        }
        if (!readAllRestarting(controlSocketFd, &packet.base + 1,
                               packet.base.size - sizeof(packet.base))) {
            readFailure();
        }
        packetHandlerFunc(userObj, packet.base);
    }
}
