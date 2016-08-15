#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pty.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "../common/SocketIo.h"

namespace {

static int connectSocket(int port, const std::string &key) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);

    setSocketNoDelay(s);

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int connectRet = connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    assert(connectRet == 0);

    size_t i = 0;
    while (i < key.size()) {
        const size_t remaining = key.size() - i;
        const ssize_t actual = write(s, &key[i], remaining);
        assert(actual > 0 && static_cast<size_t>(actual) <= remaining);
        i += actual;
    }

    return s;
}

struct Child {
    pid_t pid;
    int masterfd;
};

static Child spawnChild(int cols, int rows) {
    int masterfd = 0;
    winsize ws = {};
    ws.ws_col = cols;
    ws.ws_row = rows;
    const pid_t pid = forkpty(&masterfd, nullptr, nullptr, &ws);
    if (pid == 0) {
        execl("/bin/bash", "/bin/bash", nullptr);
        abort();
    }
    return Child { pid, masterfd };
}

struct IoLoop {
    std::mutex windowMutex;
    std::condition_variable windowIncrease;
    std::atomic<int32_t> window = {0};
    int controlSocketFd = -1;
    int childFd = -1;
};

static void writePacket(IoLoop &ioloop, const Packet &p) {
    if (!writeAllRestarting(ioloop.controlSocketFd,
            reinterpret_cast<const char*>(&p), sizeof(p))) {
        connectionBrokenAbort();
    }
}

static void socketToPtyThread(IoLoop *ioloop, int socketFd) {
    std::array<char, 8192> buf;
    while (true) {
        const ssize_t amt1 = readRestarting(socketFd, buf.data(), buf.size());
        if (amt1 <= 0) {
            // The data socket may have been shutdown, so ignore this
            // situation.
            break;
        }
        // If the child process exits, this write could fail.  In that case,
        // ignore the failure, but continue to flush I/O from the pty.
        writeAllRestarting(ioloop->childFd, buf.data(), amt1);
    }
}

static void ptyToSocketThread(IoLoop *ioloop, int socketFd) {
    std::array<char, 32 * 1024> buf;
    int32_t locWindow = kOutputWindowSize;
    const int32_t kThreshold = kOutputWindowSize / 4;
    while (true) {
        if (locWindow < kThreshold) {
            locWindow += ioloop->window.exchange(0);
            if (locWindow < kThreshold) {
                std::unique_lock<std::mutex> lock(ioloop->windowMutex);
                while (true) {
                    locWindow += ioloop->window.exchange(0);
                    if (locWindow < kThreshold) {
                        ioloop->windowIncrease.wait(lock);
                    } else {
                        break;
                    }
                }
            }
        }
        const ssize_t amt1 =
            readRestarting(ioloop->childFd, buf.data(),
                std::min<size_t>(buf.size(), locWindow));
        if (amt1 <= 0) {
            // The pty has closed.  Shutdown I/O on the data socket to signal
            // I/O completion to the frontend.
            shutdown(socketFd, SHUT_RDWR);
            break;
        }
        if (!writeAllRestarting(socketFd, buf.data(), amt1)) {
            connectionBrokenAbort();
        }
        locWindow -= amt1;
    }
}

static void handlePacket(IoLoop *ioloop, const Packet &p) {
    switch (p.type) {
        case Packet::Type::SetSize: {
            winsize ws = {};
            ws.ws_col = p.u.termSize.cols;
            ws.ws_row = p.u.termSize.rows;
            ioctl(ioloop->childFd, TIOCSWINSZ, &ws);
            break;
        }
        case Packet::Type::IncreaseWindow: {
            {
                std::lock_guard<std::mutex> guard(ioloop->windowMutex);
                ioloop->window += p.u.windowAmount;
            }
            ioloop->windowIncrease.notify_one();
            break;
        }
        default: {
            fprintf(stderr, "internal error: unexpected packet %d\n",
                static_cast<int>(p.type));
            exit(1);
        }
    }
}

static void mainLoop(int controlSocketFd, int dataSocketFd, Child child) {
    IoLoop ioloop;
    ioloop.controlSocketFd = controlSocketFd;
    ioloop.childFd = child.masterfd;
    std::thread s2p(socketToPtyThread, &ioloop, dataSocketFd);
    std::thread p2s(ptyToSocketThread, &ioloop, dataSocketFd);
    std::thread rcs(readControlSocketThread<IoLoop, handlePacket>, controlSocketFd, &ioloop);

    // Block until the child process finishes, then notify the frontend of
    // child exit.
    int exitStatus = 0;
    if (waitpid(child.pid, &exitStatus, 0) != child.pid) {
        perror("waitpid failed");
        exit(1);
    }
    if (WIFEXITED(exitStatus)) {
        exitStatus = WEXITSTATUS(exitStatus);
    } else {
        // XXX: I'm just making something up here.  I've got
        // no idea whether this makes sense.
        exitStatus = 1;
    }
    Packet p = { Packet::Type::ChildExitStatus };
    p.u.exitStatus = exitStatus;
    writePacket(ioloop, p);

    // Ensure that the parent thread outlives its child threads.  The program
    // should exit before these threads finish.
    s2p.join();
    p2s.join();
    rcs.join();
}

} // namespace

int main(int argc, char *argv[]) {
    assert(argc == 6);

    const int controlSocketPort = atoi(argv[1]);
    const int dataSocketPort = atoi(argv[2]);
    const std::string key = argv[3];
    const int cols = atoi(argv[4]);
    const int rows = atoi(argv[5]);

    const int controlSocket = connectSocket(controlSocketPort, key);
    const int dataSocket = connectSocket(dataSocketPort, key);

    const auto child = spawnChild(cols, rows);

    mainLoop(controlSocket, dataSocket, child);

    return 0;
}
