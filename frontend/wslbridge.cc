#include <windows.h>

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
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

#include <algorithm>
#include <array>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "../common/SocketIo.h"

#define BACKEND_PROGRAM "wslbridge-backend"

// SystemFunction036 is also known as RtlGenRandom.  It might be possible to
// replace this with getentropy, if not now, then later.
extern "C" BOOLEAN WINAPI SystemFunction036(PVOID, ULONG);

namespace {

const int32_t kOutputWindowSize = 8192;

static WakeupFd *g_wakeupFd = nullptr;

static TermSize terminalSize() {
    winsize ws = {};
    if (isatty(STDIN_FILENO) && ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
        return TermSize { ws.ws_col, ws.ws_row };
    } else {
        return TermSize { 80, 24 };
    }
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
    s_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
        fatal("error: mbsToWcs: invalid string\n");
    }
    std::wstring ret;
    ret.resize(len);
    const size_t len2 = mbstowcs(&ret[0], s.c_str(), len);
    assert(len == len2);
    return ret;
}

static std::string wcsToMbs(const std::wstring &s) {
    const size_t len = wcstombs(nullptr, s.c_str(), 0);
    if (len == static_cast<size_t>(-1)) {
        fatal("error: wcsToMbs: invalid string\n");
    }
    std::string ret;
    ret.resize(len);
    const size_t len2 = wcstombs(&ret[0], s.c_str(), len);
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
        fatal("error: key check failed\n");
    }
    return cs;
}

class TerminalState {
private:
    std::mutex mutex_;
    bool inRawMode_ = false;
    bool modeValid_[2] = {false, false};
    termios mode_[2] = {};

public:
    void enterRawMode();

private:
    void leaveRawMode(const std::lock_guard<std::mutex> &lock);

public:
    void fatal(const char *fmt, ...)
        __attribute__((noreturn))
        __attribute__((format(printf, 2, 3)));
    void fatalv(const char *fmt, va_list ap) __attribute__((noreturn));
    void exitCleanly(int exitStatus);
};

// Put the input terminal into non-canonical mode.
void TerminalState::enterRawMode() {
    std::lock_guard<std::mutex> lock(mutex_);

    assert(!inRawMode_);
    inRawMode_ = true;

    for (int i = 0; i < 2; ++i) {
        if (!isatty(i)) {
            modeValid_[i] = false;
        } else {
            if (tcgetattr(i, &mode_[i]) < 0) {
                fatalPerror("tcgetattr failed");
            }
            modeValid_[i] = true;
        }
    }

    if (modeValid_[0]) {
        termios buf;
        if (tcgetattr(0, &buf) < 0) {
            fatalPerror("tcgetattr failed");
        }
        buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
        buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        buf.c_cflag &= ~(CSIZE | PARENB);
        buf.c_cflag |= CS8;
        buf.c_cc[VMIN] = 1;  // blocking read
        buf.c_cc[VTIME] = 0;
        if (tcsetattr(0, TCSAFLUSH, &buf) < 0) {
            fatalPerror("tcsetattr failed");
        }
    }

    if (modeValid_[1]) {
        termios buf;
        if (tcgetattr(1, &buf) < 0) {
            fatalPerror("tcgetattr failed");
        }
        buf.c_cflag &= ~(CSIZE | PARENB);
        buf.c_cflag |= CS8;
        buf.c_oflag &= ~OPOST;
        if (tcsetattr(1, TCSAFLUSH, &buf) < 0) {
            fatalPerror("tcsetattr failed");
        }
    }
}

void TerminalState::leaveRawMode(const std::lock_guard<std::mutex> &lock) {
    if (!inRawMode_) {
        return;
    }
    for (int i = 0; i < 2; ++i) {
        if (modeValid_[i]) {
            if (tcsetattr(i, TCSAFLUSH, &mode_[i]) < 0) {
                fatalPerror("error restoring terminal mode");
            }
        }
    }
}

// This function cannot be used from a signal handler.
void TerminalState::fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    this->fatalv(fmt, ap);
    va_end(ap);
}

void TerminalState::fatalv(const char *fmt, va_list ap) {
    std::lock_guard<std::mutex> lock(mutex_);
    leaveRawMode(lock);
    ::fatalv(fmt, ap);
}

void TerminalState::exitCleanly(int exitStatus) {
    std::lock_guard<std::mutex> lock(mutex_);
    leaveRawMode(lock);
    fflush(stdout);
    fflush(stderr);
    // Avoid calling exit, which would call global destructors and destruct the
    // WakeupFd object.
    _exit(exitStatus);
}

static TerminalState g_terminalState;

struct IoLoop {
    std::string spawnProgName;
    bool usePty = false;
    std::mutex mutex;
    bool ioFinished = false;
    int controlSocketFd = -1;
    bool childReaped = false;
    int childExitStatus = -1;
};

static void fatalConnectionBroken() {
    g_terminalState.fatal("\nwslbridge error: connection broken\n");
}

static void writePacket(IoLoop &ioloop, const Packet &p) {
    std::lock_guard<std::mutex> lock(ioloop.mutex);
    if (!writeAllRestarting(ioloop.controlSocketFd,
            reinterpret_cast<const char*>(&p), sizeof(p))) {
        fatalConnectionBroken();
    }
}

static void parentToSocketThread(int socketFd) {
    std::array<char, 8192> buf;
    while (true) {
        const ssize_t amt1 = readRestarting(STDIN_FILENO, buf.data(), buf.size());
        if (amt1 <= 0) {
            // If we reach EOF reading from stdin, propagate EOF to the child.
            close(socketFd);
            break;
        }
        if (!writeAllRestarting(socketFd, buf.data(), amt1)) {
            // We don't propagate EOF backwards, but we do let data build up.
            break;
        }
    }
}

static void socketToParentThread(IoLoop *ioloop, bool isErrorPipe, int socketFd, int outFd) {
    uint32_t bytesWritten = 0;
    std::array<char, 32 * 1024> buf;
    while (true) {
        const ssize_t amt1 = readRestarting(socketFd, buf.data(), buf.size());
        if (amt1 == 0) {
            std::lock_guard<std::mutex> lock(ioloop->mutex);
            ioloop->ioFinished = true;
            g_wakeupFd->set();
            break;
        }
        if (amt1 < 0) {
            break;
        }
        if (!writeAllRestarting(outFd, buf.data(), amt1)) {
            if (!ioloop->usePty && !isErrorPipe) {
                // ssh seems to propagate an stdout EOF backwards to the remote
                // program, so do the same thing.  It doesn't do this for
                // stderr, though, where the remote process is allowed to block
                // forever.
                Packet p = { Packet::Type::CloseStdoutPipe };
                writePacket(*ioloop, p);
            }
            shutdown(socketFd, SHUT_RDWR);
            break;
        }
        bytesWritten += amt1;
        if (bytesWritten >= kOutputWindowSize / 2) {
            Packet p = { Packet::Type::IncreaseWindow };
            p.u.window.amount = bytesWritten;
            p.u.window.isErrorPipe = isErrorPipe;
            writePacket(*ioloop, p);
            bytesWritten = 0;
        }
    }
}

static void handlePacket(IoLoop *ioloop, const Packet &p) {
    switch (p.type) {
        case Packet::Type::ChildExitStatus: {
            std::lock_guard<std::mutex> lock(ioloop->mutex);
            ioloop->childReaped = true;
            ioloop->childExitStatus = p.u.exitStatus;
            g_wakeupFd->set();
            break;
        }
        case Packet::Type::SpawnFailed: {
            std::string msg;
            if (p.u.spawnError.type == SpawnError::Type::ForkPtyFailed) {
                msg = "error: forkpty failed: ";
            } else {
                msg = "error: could not start '" + ioloop->spawnProgName + "': ";
            }
            msg += errorString(p.u.spawnError.error);
            g_terminalState.fatal("%s\n", msg.c_str());
            break;
        }
        default: {
            g_terminalState.fatal("internal error: unexpected packet %d\n",
                static_cast<int>(p.type));
        }
    }
}

static void mainLoop(const std::string &spawnProgName,
                     bool usePty, int controlSocketFd,
                     int inputSocketFd, int outputSocketFd, int errorSocketFd,
                     TermSize termSize) {
    IoLoop ioloop;
    ioloop.spawnProgName = spawnProgName;
    ioloop.usePty = usePty;
    ioloop.controlSocketFd = controlSocketFd;
    std::thread p2s(parentToSocketThread, inputSocketFd);
    std::thread s2p(socketToParentThread, &ioloop, false, outputSocketFd, STDOUT_FILENO);
    std::unique_ptr<std::thread> es2p;
    if (errorSocketFd != -1) {
        es2p = std::unique_ptr<std::thread>(
            new std::thread(socketToParentThread, &ioloop, true, errorSocketFd, STDERR_FILENO));
    }
    std::thread rcs(readControlSocketThread<IoLoop, handlePacket, fatalConnectionBroken>,
                    controlSocketFd, &ioloop);
    int32_t exitStatus = -1;

    while (true) {
        g_wakeupFd->wait();
        const auto newSize = terminalSize();
        if (newSize != termSize) {
            Packet p = { Packet::Type::SetSize };
            p.u.termSize = termSize = newSize;
            writePacket(ioloop, p);
        }
        std::lock_guard<std::mutex> lock(ioloop.mutex);
        if (ioloop.childReaped && ioloop.ioFinished) {
            exitStatus = ioloop.childExitStatus;
            break;
        }
    }

    // Socket-to-pty I/O is finished already.
    s2p.join();

    // We can't return, because the threads could still be running.  Rather
    // than shut them down gracefully, which seems hard(?), just let the OS
    // clean everything up.
    g_terminalState.exitCleanly(exitStatus);
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
        fatal("error: GetModuleHandleEx failed\n");
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
        fatal("error: '%s' backend program is missing\n",
            wcsToMbs(ret).c_str());
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
            return L'\0';
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
            ret.push_back(drive);
            ret.append(path.substr(2));
            for (wchar_t &ch : ret) {
                if (ch == L'\\') {
                    ch = L'/';
                }
            }
            return ret;
        }
    }
    fatal(
        "Error: the backend program '%s' must be located on a "
        "letter drive so WSL can access it with a /mnt/<LTR> path.\n",
        wcsToMbs(path).c_str());
}

std::wstring findSystemProgram(const wchar_t *name) {
    std::array<wchar_t, MAX_PATH> windir;
    windir[0] = L'\0';
    if (GetWindowsDirectoryW(windir.data(), windir.size()) == 0) {
        fatal("error: GetWindowsDirectory call failed\n");
    }
    const wchar_t *const kPart32 = L"\\System32\\";
    const auto path = [&](const wchar_t *part) -> std::wstring {
        return std::wstring(windir.data()) + part + name;
    };
#if defined(__x86_64__)
    const auto ret = path(kPart32);
    if (pathExists(ret)) {
        return ret;
    } else {
        fatal("error: '%s' does not exist\n"
              "note: Ubuntu-on-Windows must be installed\n",
              wcsToMbs(ret).c_str());
    }
#elif defined(__i386__)
    const wchar_t *const kPartNat = L"\\Sysnative\\";
    const auto pathNat = path(kPartNat);
    if (pathExists(pathNat)) {
        return std::move(pathNat);
    }
    const auto path32 = path(kPart32);
    if (pathExists(path32)) {
        return std::move(path32);
    }
    fatal("error: neither '%s' nor '%s' exist\n"
          "note: Ubuntu-on-Windows must be installed\n",
          wcsToMbs(pathNat).c_str(), wcsToMbs(path32).c_str());
#else
    #error "Could not determine architecture"
#endif
}

static void usage(const char *prog) {
    printf("Usage: %s [options] [--] [command]...\n", prog);
    printf("Runs a program within a Windows Subsystem for Linux (WSL) pty\n");
    printf("\n");
    printf("Options:\n");
    printf("  -e VAR        Copies VAR into the WSL environment.\n");
    printf("  -e VAR=VAL    Sets VAR to VAL in the WSL environment.\n");
    printf("  -T            Do not use a pty.\n");
    printf("  -t            Use a pty (as long as stdin is a tty).\n");
    printf("  -t -t         Force a pty (even if stdin is not a tty).\n");
    exit(0);
}

class Environment {
public:
    void set(const std::string &var) {
        const char *value = getenv(var.c_str());
        if (value != nullptr) {
            set(var, value);
        }
    }

    void set(const std::string &var, const std::string &value) {
        pairs_.push_back(std::make_pair(mbsToWcs(var), mbsToWcs(value)));
    }

    bool hasVar(const std::wstring &var) {
        for (const auto &pair : pairs_) {
            if (pair.first == var) {
                return true;
            }
        }
        return false;
    }

    const std::vector<std::pair<std::wstring, std::wstring>> &pairs() { return pairs_; }

private:
    std::vector<std::pair<std::wstring, std::wstring>> pairs_;
};

static void appendBashArg(std::wstring &out, const std::wstring &arg) {
    if (!out.empty()) {
        out.push_back(L' ');
    }
    const auto isCharSafe = [](wchar_t ch) -> bool {
        switch (ch) {
            case L'%':
            case L'+':
            case L',':
            case L'-':
            case L'.':
            case L'/':
            case L':':
            case L'=':
            case L'@':
            case L'_':
            case L'{':
            case L'}':
                return true;
            default:
                return (ch >= L'0' && ch <= L'9') ||
                       (ch >= L'a' && ch <= L'z') ||
                       (ch >= L'A' && ch <= L'Z');
        }
    };
    if (arg.empty()) {
        out.append(L"''");
        return;
    }
    if (std::all_of(arg.begin(), arg.end(), isCharSafe)) {
        out.append(arg);
        return;
    }
    bool inQuote = false;
    const auto enterQuote = [&](bool newInQuote) {
        if (inQuote != newInQuote) {
            out.push_back(L'\'');
            inQuote = newInQuote;
        }
    };
    for (auto ch : arg) {
        if (ch == L'\'') {
            enterQuote(false);
            out.append(L"\\'");
        } else if (isCharSafe(ch)) {
            out.push_back(ch);
        } else {
            enterQuote(true);
            out.push_back(ch);
        }
    }
    enterQuote(false);
}

static std::string errorMessageToString(DWORD err) {
    // Use FormatMessageW rather than FormatMessageA, because we want to use
    // wcstombs to convert to the Cygwin locale, which might not match the
    // codepage FormatMessageA would use.  We need to convert using wcstombs,
    // rather than print using %ls, because %ls doesn't work in the original
    // MSYS.
    wchar_t *wideMsgPtr = NULL;
    const DWORD formatRet = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<wchar_t*>(&wideMsgPtr),
        0,
        NULL);
    if (formatRet == 0 || wideMsgPtr == NULL) {
        return std::string();
    }
    std::string msg = wcsToMbs(wideMsgPtr);
    LocalFree(wideMsgPtr);
    const size_t pos = msg.find_last_not_of(" \r\n\t");
    if (pos == std::string::npos) {
        msg.clear();
    } else {
        msg.erase(pos + 1);
    }
    return msg;
}

static std::string formatErrorMessage(DWORD err) {
    char buf[64];
    sprintf(buf, "error %#x", static_cast<unsigned int>(err));
    std::string ret = errorMessageToString(err);
    if (ret.empty()) {
        ret += buf;
    } else {
        ret += " (";
        ret += buf;
        ret += ")";
    }
    return ret;
}

} // namespace

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "");
    g_wakeupFd = new WakeupFd();

    Environment env;
    enum class TtyRequest { Auto, Yes, No, Force } ttyRequest = TtyRequest::Auto;

    int debugFork = 0;
    int c = 0;
    const struct option kOptionTable[] = {
        { "help",           false, nullptr,     'h' },
        { "debug-fork",     false, &debugFork,  1   },
        { nullptr,          false, nullptr,     0   },
    };
    while ((c = getopt_long(argc, argv, "+e:tT", kOptionTable, nullptr)) != -1) {
        switch (c) {
            case 0:
                // Ignore long option.
                break;
            case 'e': {
                const char *eq = strchr(optarg, '=');
                const auto varname = eq ? std::string(optarg, eq - optarg) : std::string(optarg);
                if (varname.empty()) {
                    fatal("error: -e variable name cannot be empty: '%s'\n", optarg);
                }
                if (eq) {
                    env.set(varname, eq + 1);
                } else {
                    env.set(varname);
                }
                break;
            }
            case 'h':
                usage(argv[0]);
                break;
            case 't':
                if (ttyRequest == TtyRequest::Yes) {
                    ttyRequest = TtyRequest::Force;
                } else {
                    ttyRequest = TtyRequest::Yes;
                }
                break;
            case 'T':
                ttyRequest = TtyRequest::No;
                break;
            default:
                fatal("Try '%s --help' for more information.\n", argv[0]);
        }
    }

    const bool hasCommand = optind < argc;
    if (ttyRequest == TtyRequest::Auto) {
        ttyRequest = hasCommand ? TtyRequest::No : TtyRequest::Yes;
    }
    if (ttyRequest == TtyRequest::Yes && !isatty(STDIN_FILENO)) {
        fprintf(stderr, "Pseudo-terminal will not be allocated because stdin is not a terminal.\n");
        ttyRequest = TtyRequest::No;
    }
    const bool usePty = ttyRequest != TtyRequest::No;

    if (!env.hasVar(L"TERM")) {
        // This seems to be what OpenSSH is doing.
        if (usePty) {
            const char *termVal = getenv("TERM");
            env.set("TERM", termVal && *termVal ? termVal : "dumb");
        } else {
            env.set("TERM", "dumb");
        }
    }

    // We must register this handler *before* determining the initial terminal
    // size.
    struct sigaction sa = {};
    sa.sa_handler = [](int signo) { g_wakeupFd->set(); };
    sa.sa_flags = SA_RESTART;
    ::sigaction(SIGWINCH, &sa, nullptr);
    sa = {};
    // We want to handle EPIPE rather than receiving SIGPIPE.
    signal(SIGPIPE, SIG_IGN);

    Socket controlSocket;
    Socket inputSocket;
    Socket outputSocket;
    std::unique_ptr<Socket> errorSocket;
    if (!usePty) {
        errorSocket = std::unique_ptr<Socket>(new Socket);
    }

    const std::wstring bashPath = findSystemProgram(L"bash.exe");
    const std::wstring backendPath = convertPathToWsl(findBackendProgram());
    const auto initialSize = terminalSize();
    const std::string key = randomString();

    // Prepare the backend command line.
    std::wstring bashCmdLine;
    appendBashArg(bashCmdLine, backendPath);
    if (debugFork) {
        appendBashArg(bashCmdLine, L"--debug-fork");
    }

    std::array<wchar_t, 1024> buffer;
    int iRet = swprintf(buffer.data(), buffer.size(),
                        L" -3%d -0%d -1%d -k%s -w%d -t%d",
                        controlSocket.port(),
                        inputSocket.port(),
                        outputSocket.port(),
                        key.c_str(),
                        kOutputWindowSize,
                        kOutputWindowSize / 4);
    assert(iRet > 0);
    bashCmdLine.append(buffer.data());

    if (usePty) {
        iRet = swprintf(buffer.data(), buffer.size(),
                        L" --pty -c%d -r%d",
                        initialSize.cols,
                        initialSize.rows);
    } else {
        iRet = swprintf(buffer.data(), buffer.size(),
                        L" --pipes -2%d",
                        errorSocket->port());
    }
    assert(iRet > 0);
    bashCmdLine.append(buffer.data());

    for (const auto &envPair : env.pairs()) {
        appendBashArg(bashCmdLine, L"-e" + envPair.first + L"=" + envPair.second);
    }
    appendBashArg(bashCmdLine, L"--");

    std::string spawnProgName;
    if (optind == argc) {
        // No command-line specified.  Use a default one.
        spawnProgName = "/bin/bash";
        appendBashArg(bashCmdLine, L"/bin/bash");
    } else {
        spawnProgName = argv[optind];
        for (int i = optind; i < argc; ++i) {
            appendBashArg(bashCmdLine, mbsToWcs(argv[i]));
        }
    }

    std::wstring cmdLine;
    cmdLine.append(L"\"");
    cmdLine.append(bashPath);
    cmdLine.append(L"\" -c ");
    appendBashArg(cmdLine, bashCmdLine);

    STARTUPINFOW sui = {};
    sui.cb = sizeof(sui);
    PROCESS_INFORMATION pi = {};
    BOOL success = CreateProcessW(bashPath.c_str(), &cmdLine[0], nullptr, nullptr,
        false,
        debugFork ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW,
        nullptr, nullptr, &sui, &pi);
    if (!success) {
        fatal("error starting bash.exe adapter: %s\n",
            formatErrorMessage(GetLastError()).c_str());
    }

    // If the backend process exits before the frontend, then something has
    // gone wrong.
    const auto watchdog = std::thread([=]() {
        WaitForSingleObject(pi.hProcess, INFINITE);
        g_terminalState.fatal("\nwslbridge error: backend process died\n");
    });

    const int controlSocketC = acceptClientAndAuthenticate(controlSocket, key);
    const int inputSocketC = acceptClientAndAuthenticate(inputSocket, key);
    const int outputSocketC = acceptClientAndAuthenticate(outputSocket, key);
    const int errorSocketC = !errorSocket ? -1 : acceptClientAndAuthenticate(*errorSocket, key);
    controlSocket.close();
    inputSocket.close();
    outputSocket.close();
    if (errorSocket) { errorSocket->close(); }

    if (usePty) {
        g_terminalState.enterRawMode();
    }

    mainLoop(spawnProgName,
             usePty, controlSocketC,
             inputSocketC, outputSocketC, errorSocketC,
             initialSize);
    return 0;
}
