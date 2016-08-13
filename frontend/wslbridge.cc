#include <windows.h>

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <utility>
#include <string>

#include "../common/SocketIo.h"

#define BACKEND_PROGRAM "wslbridge-backend"

// SystemFunction036 is also known as RtlGenRandom.  It might be possible to
// replace this with getentropy, if not now, then later.
extern "C" BOOLEAN WINAPI SystemFunction036(PVOID, ULONG);

namespace {

static WakeupFd g_wakeupFd;

static void terminalResized(int signo) {
    g_wakeupFd.set();
}

static void registerResizeSignalHandler() {
    struct sigaction sa = {};
    sa.sa_handler = terminalResized;
    sa.sa_flags = SA_RESTART;
    ::sigaction(SIGWINCH, &sa, nullptr);
}

static TermSize terminalSize() {
    winsize ws = {};
    ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
    return std::make_pair(ws.ws_col, ws.ws_row);
}

class Socket {
public:
    Socket();
    ~Socket() { close(); }
    int port() { return port_; }
    int accept();
    void close();

private:
    int s_;
    int port_;
};

Socket::Socket() {
    s_ = socket(AF_INET, SOCK_STREAM, 0);
    assert(s_ >= 0);

    setSocketNoDelay(s_);

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int bindRet = bind(s_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    assert(bindRet == 0);

    const int listenRet = listen(s_, 1);
    assert(listenRet == 0);

    socklen_t addrLen = sizeof(addr);
    const int getRet = getsockname(s_, reinterpret_cast<sockaddr*>(&addr), &addrLen);
    assert(getRet == 0);

    port_ = ntohs(addr.sin_port);
}

int Socket::accept() {
    const int cs = ::accept(s_, nullptr, nullptr);
    assert(cs >= 0);
    setSocketNoDelay(cs);
    return cs;
}

void Socket::close() {
    if (s_ != -1) {
        ::close(s_);
        s_ = -1;
    }
}

static std::string randomString() {
    char buf[32] = {};
    if (!SystemFunction036(&buf, sizeof(buf))) {
        assert(false && "RtlGenRandom failed");
    }
    std::string out;
    for (char ch : buf) {
        out.push_back("0123456789ABCDEF"[(ch >> 4) & 0xF]);
        out.push_back("0123456789ABCDEF"[(ch >> 0) & 0xF]);
    }
    return out;
}

static std::wstring mbsToWcs(const std::string &s) {
    const size_t len = mbstowcs(nullptr, s.c_str(), 0);
    if (len == static_cast<size_t>(-1)) {
        assert(false && "mbsToWcs: invalid string");
    }
    std::wstring ret;
    ret.resize(len);
    const size_t len2 = mbstowcs(&ret[0], s.c_str(), len);
    assert(len == len2);
    return ret;
}

// As long as clients only get one chance to provide a key, this function
// should be unnecessary.
static bool secureStrEqual(const std::string &x, const std::string &y) {
    if (x.size() != y.size()) {
        return false;
    }
    volatile char ch = 0;
    volatile const char *xp = &x[0];
    volatile const char *yp = &y[0];
    for (size_t i = 0; i < x.size(); ++i) {
        ch |= (xp[i] ^ yp[i]);
    }
    return ch == 0;
}

static int acceptClientAndAuthenticate(Socket &socket, const std::string &key) {
    const int cs = socket.accept();
    std::string checkBuf;
    checkBuf.resize(key.size());
    size_t i = 0;
    while (i < checkBuf.size()) {
        const size_t remaining = checkBuf.size() - i;
        const ssize_t actual = read(cs, &checkBuf[i], remaining);
        assert(actual > 0 && static_cast<size_t>(actual) <= remaining);
        i += actual;
    }
    if (!secureStrEqual(checkBuf, key)) {
        fprintf(stderr, "key check failed\n");
        exit(1);
    }
    return cs;
}

struct SavedTermiosMode {
    termios mode[2];
};

// Put the input terminal into non-canonical mode.
static SavedTermiosMode setRawTerminalMode() {
    SavedTermiosMode ret = {};
    const char *const kNames[2] = { "stdin", "stdout" };

    for (int i = 0; i < 2; ++i) {
        // XXX: These restrictions are probably excessive?
        if (!isatty(i)) {
            fprintf(stderr, "%s is not a tty\n", kNames[i]);
            exit(1);
        }
        if (tcgetattr(i, &ret.mode[i]) < 0) {
            perror("tcgetattr failed");
            exit(1);
        }
    }

    {
        termios buf;
        if (tcgetattr(0, &buf) < 0) {
            perror("tcgetattr failed");
            exit(1);
        }
        buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
        buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        buf.c_cflag &= ~(CSIZE | PARENB);
        buf.c_cflag |= CS8;
        buf.c_cc[VMIN] = 1;  // blocking read
        buf.c_cc[VTIME] = 0;
        if (tcsetattr(0, TCSAFLUSH, &buf) < 0) {
            fprintf(stderr, "tcsetattr failed\n");
            exit(1);
        }
    }

    {
        termios buf;
        if (tcgetattr(1, &buf) < 0) {
            perror("tcgetattr failed");
            exit(1);
        }
        buf.c_cflag &= ~(CSIZE | PARENB);
        buf.c_cflag |= CS8;
        buf.c_oflag &= ~OPOST;
        if (tcsetattr(1, TCSAFLUSH, &buf) < 0) {
            fprintf(stderr, "tcsetattr failed\n");
            exit(1);
        }
    }

    return ret;
}

static void restoreTerminalMode(const SavedTermiosMode &original) {
    for (int i = 0; i < 2; ++i) {
        if (tcsetattr(i, TCSAFLUSH, &original.mode[i]) < 0) {
            perror("error restoring terminal mode");
            exit(1);
        }
    }
}

static int mainLoop(int controlSocketFd, int dataSocketFd, TermSize termSize) {

    ControlSocket controlSocket(controlSocketFd);
    IoChannel parentToSocket(STDIN_FILENO, dataSocketFd);
    IoChannel socketToParent(dataSocketFd, STDOUT_FILENO);

    fd_set readfds;
    fd_set writefds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    parentToSocket.setWindow(kFrontendToBackendWindow);

    bool childReaped = false;
    int childExitStatus = -1;

    while (!controlSocket.hasFailed() &&
            !parentToSocket.hasReadFailed() &&
            !socketToParent.hasWriteFailed()) {
        int maxfd = -1;
        controlSocket.prepareForSelect(maxfd, &readfds, &writefds);
        socketToParent.prepareForSelect(maxfd, &readfds, &writefds);
        parentToSocket.prepareForSelect(maxfd, &readfds, &writefds);
        assert(maxfd != -1);

        FD_SET(g_wakeupFd.readFd(), &readfds);
        maxfd = std::max(maxfd, g_wakeupFd.readFd());

        const int status = select(maxfd + 1, &readfds, &writefds, nullptr, nullptr);
        if (status < 0) {
            if (errno != EINTR) {
                perror("select failed");
                exit(1);
            }
        } else {
            controlSocket.serviceIo(&readfds, &writefds);
            socketToParent.serviceIo(&readfds, &writefds);
            parentToSocket.serviceIo(&readfds, &writefds);

            if (FD_ISSET(g_wakeupFd.readFd(), &readfds)) {
                const auto newSize = terminalSize();
                if (newSize != termSize) {
                    Packet p = {};
                    p.type = Packet::Type::SetSize;
                    p.u.size = newSize;
                    termSize = newSize;
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
                case Packet::Type::IncreaseWindow:
                    parentToSocket.increaseWindow(p.u.amount);
                    break;
                case Packet::Type::ChildExitStatus:
                    childReaped = true;
                    childExitStatus = p.u.exitStatus;
                    break;
                default:
                    break;
            }
        }

        if (socketToParent.bytesWritten() >= kBackendToFrontendWindow / 2) {
            Packet p = {};
            p.type = Packet::Type::IncreaseWindow;
            p.u.amount = socketToParent.bytesWritten();
            socketToParent.resetBytesWritten();
            controlSocket.write(&p, sizeof(p));
        }

        if (childReaped &&
                socketToParent.hasReadFailed() &&
                socketToParent.isBufferEmpty()) {
            // Normal exit path: the child has exited, we have its exit code,
            // the pty is closed, and we've written everything we can to the
            // parent pty.
            return childExitStatus;
        }
    }
    fprintf(stderr, "wslbridge: broken connection\r\n");
    return 1;
}

static bool pathExists(const std::wstring &path) {
    return GetFileAttributesW(path.c_str()) != 0xFFFFFFFF;
}

static std::wstring dirname(const std::wstring &path) {
    std::wstring::size_type pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return L"";
    } else {
        return path.substr(0, pos);
    }
}

static HMODULE getCurrentModule() {
    HMODULE module;
    if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(getCurrentModule),
                &module)) {
        fprintf(stderr, "error: GetModuleHandleEx failed\n");
        exit(1);
    }
    return module;
}

static std::wstring getModuleFileName(HMODULE module) {
    const int bufsize = 4096;
    wchar_t path[bufsize];
    int size = GetModuleFileNameW(module, path, bufsize);
    assert(size != 0 && size != bufsize);
    return std::wstring(path);
}

std::wstring findBackendProgram() {
    std::wstring progDir = dirname(getModuleFileName(getCurrentModule()));
    std::wstring ret = progDir + (L"\\" BACKEND_PROGRAM);
    if (!pathExists(ret)) {
        fprintf(stderr, "error: '%ls' backend program is missing\n", ret.c_str());
        exit(1);
    }
    return ret;
}

std::wstring convertPathToWsl(const std::wstring &path) {
    const auto lowerDrive = [](wchar_t ch) -> wchar_t {
        if (ch >= L'a' && ch <= L'z') {
            return ch;
        } else if (ch >= L'A' && ch <= 'Z') {
            return ch - L'A' + L'a';
        } else {
            return false;
        }
    };
    const auto isSlash = [](wchar_t ch) -> bool {
        return ch == L'/' || ch == L'\\';
    };
    if (path.size() >= 3) {
        const wchar_t drive = lowerDrive(path[0]);
        if (drive && path[1] == L':' && isSlash(path[2])) {
            // Acceptable path.
            std::wstring ret = L"/mnt/";
            ret.push_back(static_cast<wchar_t>(tolower(path[0])));
            ret.push_back(L'/');
            ret.append(path.substr(2));
            for (wchar_t &ch : ret) {
                if (ch == L'\\') {
                    ch = L'/';
                }
            }
            return ret;
        }
    }
    fprintf(stderr,
        "Error: the backend program '%ls' must be located on a "
        "letter drive so WSL can access it with a /mnt/<LTR> path.\n",
        path.c_str());
    exit(1);
}

} // namespace

int main() {
    setlocale(LC_ALL, "");

    registerResizeSignalHandler();

    Socket controlSocket;
    Socket dataSocket;

    const bool kUseCmdToDebug = false;

    const auto initialSize = terminalSize();
    const std::string key = randomString();
    const std::wstring bashPath = L"C:\\windows\\system32\\bash.exe";
    const std::wstring cmdPath = L"C:\\windows\\system32\\cmd.exe";
    const std::wstring backendPath = convertPathToWsl(findBackendProgram());
    std::wstring cmdline =
        bashPath + L" -c \"" +
        backendPath +
        L" " + std::to_wstring(controlSocket.port()) +
        L" " + std::to_wstring(dataSocket.port()) +
        L" " + mbsToWcs(key) +
        L" " + std::to_wstring(initialSize.first) +
        L" " + std::to_wstring(initialSize.second) +
        L"\"";

    std::wstring appPath = bashPath;

    if (kUseCmdToDebug) {
        cmdline = cmdPath + L" /k " + cmdline;
        appPath = cmdPath;
    }

    STARTUPINFOW sui = {};
    sui.cb = sizeof(sui);
    PROCESS_INFORMATION pi = {};
    BOOL success = CreateProcessW(appPath.c_str(), &cmdline[0], nullptr, nullptr,
        false,
        kUseCmdToDebug ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW,
        nullptr, nullptr, &sui, &pi);
    assert(success && "CreateProcess failed");

    const int controlSocketC = acceptClientAndAuthenticate(controlSocket, key);
    const int dataSocketC = acceptClientAndAuthenticate(dataSocket, key);
    controlSocket.close();
    dataSocket.close();

    setSocketNonblocking(controlSocketC);
    setSocketNonblocking(dataSocketC);

    const auto termMode = setRawTerminalMode();
    const int exitStatus = mainLoop(controlSocketC, dataSocketC, initialSize);
    restoreTerminalMode(termMode);

    return exitStatus;
}
