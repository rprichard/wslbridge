#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pty.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <string>

#include "../common/SocketIo.h"

namespace {

static WakeupFd g_wakeupFd;

static void sigChldHandler(int signo) {
    g_wakeupFd.set();
}

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

static void mainLoop(int controlSocketFd, int dataSocketFd, Child child) {

    ControlSocket controlSocket(controlSocketFd);
    IoChannel socketToChild(dataSocketFd, child.masterfd);
    IoChannel childToSocket(child.masterfd, dataSocketFd);

    fd_set readfds;
    fd_set writefds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    childToSocket.setWindow(kBackendToFrontendWindow);

    bool childReaped = false;

    while (!controlSocket.hasFailed()) {
        int maxfd = -1;
        controlSocket.prepareForSelect(maxfd, &readfds, &writefds);
        socketToChild.prepareForSelect(maxfd, &readfds, &writefds);
        childToSocket.prepareForSelect(maxfd, &readfds, &writefds);
        FD_SET(g_wakeupFd.readFd(), &readfds);
        maxfd = std::max(maxfd, g_wakeupFd.readFd());
        assert(maxfd != -1);

        const int status = select(maxfd + 1, &readfds, &writefds, nullptr, nullptr);
        if (status < 0) {
            if (errno != EINTR) {
                perror("select failed");
                exit(1);
            }
        } else {
            controlSocket.serviceIo(&readfds, &writefds);
            socketToChild.serviceIo(&readfds, &writefds);
            childToSocket.serviceIo(&readfds, &writefds);

            if (FD_ISSET(g_wakeupFd.readFd(), &readfds)) {
                if (!childReaped) {
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
                    childReaped = true;
                    Packet p = {};
                    p.type = Packet::Type::ChildExitStatus;
                    p.u.exitStatus = exitStatus;
                    controlSocket.write(&p, sizeof(p));
                }
                g_wakeupFd.clear();
            }
        }

        for (int fd = 0; fd <= maxfd; ++fd) {
            FD_CLR(fd, &readfds);
            FD_CLR(fd, &writefds);
        }

        while (controlSocket.size() >= sizeof(Packet)) {
            Packet p = {};
            controlSocket.read(&p, sizeof(p));
            switch (p.type) {
                case Packet::Type::SetSize: {
                    winsize ws = {};
                    ws.ws_col = p.u.size.first;
                    ws.ws_row = p.u.size.second;
                    ioctl(child.masterfd, TIOCSWINSZ, &ws);
                    break;
                }
                case Packet::Type::IncreaseWindow:
                    childToSocket.increaseWindow(p.u.amount);
                    break;
                default:
                    break;
            }
        }

        if (socketToChild.bytesWritten() >= kFrontendToBackendWindow / 2) {
            Packet p = {};
            p.type = Packet::Type::IncreaseWindow;
            p.u.amount = socketToChild.bytesWritten();
            socketToChild.resetBytesWritten();
            controlSocket.write(&p, sizeof(p));
        }

        if (childToSocket.hasReadFailed() && childToSocket.isBufferEmpty()) {
            shutdown(dataSocketFd, SHUT_RDWR);
        }
    }
}

} // namespace

int main(int argc, char *argv[]) {
    assert(argc == 6);

    struct sigaction sa = {};
    sa.sa_handler = sigChldHandler;
    sa.sa_flags = SA_RESTART;
    ::sigaction(SIGCHLD, &sa, nullptr);

    const int controlSocketPort = atoi(argv[1]);
    const int dataSocketPort = atoi(argv[2]);
    const std::string key = argv[3];
    const int cols = atoi(argv[4]);
    const int rows = atoi(argv[5]);

    const int controlSocket = connectSocket(controlSocketPort, key);
    const int dataSocket = connectSocket(dataSocketPort, key);

    const auto child = spawnChild(cols, rows);

    setSocketNonblocking(controlSocket);
    setSocketNonblocking(dataSocket);
    mainLoop(controlSocket, dataSocket, child);

    return 0;
}
