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

struct SavedTermiosMode {
    bool valid;
    termios mode[2];
};

static WakeupFd g_wakeupFd;

static TermSize terminalSize() {
    winsize ws = {};
    ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
    return TermSize { ws.ws_col, ws.ws_row };
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
        fprintf(stderr, "error: mbsToWcs: invalid string\n");
        exit(1);
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
        fprintf(stderr, "error: wcsToMbs: invalid string\n");
        exit(1);
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
        fprintf(stderr, "key check failed\n");
        exit(1);
    }
    return cs;
}

class TerminalState {
private:
    std::mutex mutex_;
    bool inRawMode_ = false;
    termios mode_[2] = {};

public:
    void enterRawMode();

private:
    void leaveRawMode(const std::lock_guard<std::mutex> &lock);

public:
    void fatal(const char *msg);
    void exitCleanly(int exitStatus);
};

// Put the input terminal into non-canonical mode.
void TerminalState::enterRawMode() {
    std::lock_guard<std::mutex> lock(mutex_);

    assert(!inRawMode_);
    inRawMode_ = true;
    const char *const kNames[2] = { "stdin", "stdout" };

    for (int i = 0; i < 2; ++i) {
        // XXX: These restrictions are probably excessive?
        if (!isatty(i)) {
            fprintf(stderr, "%s is not a tty\n", kNames[i]);
            exit(1);
        }
        if (tcgetattr(i, &mode_[i]) < 0) {
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
}

void TerminalState::leaveRawMode(const std::lock_guard<std::mutex> &lock) {
    if (!inRawMode_) {
        return;
    }
    for (int i = 0; i < 2; ++i) {
        if (tcsetattr(i, TCSAFLUSH, &mode_[i]) < 0) {
            perror("error restoring terminal mode");
            exit(1);
        }
    }
}

// This function cannot be used from a signal handler.
void TerminalState::fatal(const char *msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    leaveRawMode(lock);
    fprintf(stderr, "\nwslbridge error: %s\n", msg);
    exit(1);
}

void TerminalState::exitCleanly(int exitStatus) {
    std::lock_guard<std::mutex> lock(mutex_);
    leaveRawMode(lock);
    exit(exitStatus);
}

static TerminalState g_terminalState;

struct IoLoop {
    std::mutex mutex;
    bool ioFinished = false;
    int controlSocketFd = -1;
    bool childReaped = false;
    int childExitStatus = -1;
};

static void fatalConnectionBroken() {
    g_terminalState.fatal("connection broken");
}

static void writePacket(IoLoop &ioloop, const Packet &p) {
    std::lock_guard<std::mutex> lock(ioloop.mutex);
    if (!writeAllRestarting(ioloop.controlSocketFd,
            reinterpret_cast<const char*>(&p), sizeof(p))) {
        fatalConnectionBroken();
    }
}

static void ptyToSocketThread(int socketFd) {
    std::array<char, 8192> buf;
    while (true) {
        const ssize_t amt1 = readRestarting(STDIN_FILENO, buf.data(), buf.size());
        if (amt1 <= 0) {
            fatalConnectionBroken();
        }
        // If the backend shuts down the socket due to end-of-stream, this
        // write could fail.  In that case, ignore the failure, but continue to
        // flush I/O from the pty.
        writeAllRestarting(socketFd, buf.data(), amt1);
    }
}

static void socketToPtyThread(IoLoop *ioloop, int socketFd) {
    uint32_t bytesWritten = 0;
    std::array<char, 32 * 1024> buf;
    while (true) {
        const ssize_t amt1 = readRestarting(socketFd, buf.data(), buf.size());
        if (amt1 == 0) {
            std::lock_guard<std::mutex> lock(ioloop->mutex);
            ioloop->ioFinished = true;
            g_wakeupFd.set();
            break;
        }
        if (amt1 < 0) {
            fatalConnectionBroken();
        }
        if (!writeAllRestarting(STDOUT_FILENO, buf.data(), amt1)) {
            fatalConnectionBroken();
        }
        bytesWritten += amt1;
        if (bytesWritten >= kOutputWindowSize / 2) {
            Packet p = { Packet::Type::IncreaseWindow };
            p.u.windowAmount = bytesWritten;
            writePacket(*ioloop, p);
            bytesWritten = 0;
        }
    }
}

static void handlePacket(IoLoop *ioloop, const Packet &p) {
    if (p.type == Packet::Type::ChildExitStatus) {
        std::lock_guard<std::mutex> lock(ioloop->mutex);
        ioloop->childReaped = true;
        ioloop->childExitStatus = p.u.exitStatus;
        g_wakeupFd.set();
    }
}

static void mainLoop(int controlSocketFd, int dataSocketFd, TermSize termSize) {
    g_terminalState.enterRawMode();
    IoLoop ioloop;
    ioloop.controlSocketFd = controlSocketFd;
    std::thread p2s(ptyToSocketThread, dataSocketFd);
    std::thread s2p(socketToPtyThread, &ioloop, dataSocketFd);
    std::thread rcs(readControlSocketThread<IoLoop, handlePacket, fatalConnectionBroken>,
                    controlSocketFd, &ioloop);
    int32_t exitStatus = -1;

    while (true) {
        g_wakeupFd.wait();
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
    fprintf(stderr,
        "Error: the backend program '%ls' must be located on a "
        "letter drive so WSL can access it with a /mnt/<LTR> path.\n",
        path.c_str());
    exit(1);
}

std::wstring findSystemProgram(const wchar_t *name) {
    std::array<wchar_t, MAX_PATH> windir;
    windir[0] = L'\0';
    if (GetWindowsDirectoryW(windir.data(), windir.size()) == 0) {
        fprintf(stderr, "error: GetWindowsDirectory call failed\n");
        exit(1);
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
        fprintf(stderr, "error: '%ls' does not exist\n", ret.c_str());
        fprintf(stderr, "note: Ubuntu-on-Windows must be installed\n");
        exit(1);
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
    fprintf(stderr, "error: neither '%ls' nor '%ls' exist\n",
        pathNat.c_str(), path32.c_str());
    fprintf(stderr, "note: Ubuntu-on-Windows must be installed\n");
    exit(1);
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

    Environment env;
    env.set("TERM");

    int c = 0;
    const struct option kOptionTable[] = {
        { "help", false, nullptr, 'h' },
        { nullptr,  false, nullptr, 0 },
    };
    while ((c = getopt_long(argc, argv, "+e:", kOptionTable, nullptr)) != -1) {
        switch (c) {
            case 'e': {
                const char *eq = strchr(optarg, '=');
                const auto varname = eq ? std::string(optarg, eq - optarg) : std::string(optarg);
                if (varname.empty()) {
                    fprintf(stderr, "error: -e variable name cannot be empty: '%s'", optarg);
                    exit(1);
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
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                exit(1);
        }
    }

    // We must register this handler *before* determining the initial terminal
    // size.
    struct sigaction sa = {};
    sa.sa_handler = [](int signo) { g_wakeupFd.set(); };
    sa.sa_flags = SA_RESTART;
    ::sigaction(SIGWINCH, &sa, nullptr);

    Socket controlSocket;
    Socket dataSocket;

    const std::wstring bashPath = findSystemProgram(L"bash.exe");
    const std::wstring backendPath = convertPathToWsl(findBackendProgram());
    const auto initialSize = terminalSize();
    const std::string key = randomString();

    // Prepare the backend command line.
    std::wstring bashCmdLine;
    appendBashArg(bashCmdLine, backendPath);
    std::array<wchar_t, 1024> buffer;
    int iRet = swprintf(buffer.data(), buffer.size(),
                        L" -s%d -d%d -k%s -c%d -r%d -w%d -t%d",
                        controlSocket.port(),
                        dataSocket.port(),
                        key.c_str(),
                        initialSize.cols,
                        initialSize.rows,
                        kOutputWindowSize,
                        kOutputWindowSize / 4);
    assert(iRet > 0);
    bashCmdLine.append(buffer.data());
    for (const auto &envPair : env.pairs()) {
        appendBashArg(bashCmdLine, L"-e" + envPair.first + L"=" + envPair.second);
    }
    appendBashArg(bashCmdLine, L"--");
    for (int i = optind; i < argc; ++i) {
        appendBashArg(bashCmdLine, mbsToWcs(argv[i]));
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
        CREATE_NO_WINDOW,
        nullptr, nullptr, &sui, &pi);
    if (!success) {
        fprintf(stderr, "error starting bash.exe adapter: %s\n",
            formatErrorMessage(GetLastError()).c_str());
        exit(1);
    }

    // If the backend process exits before the frontend, then something has
    // gone wrong.
    const auto watchdog = std::thread([=]() {
        WaitForSingleObject(pi.hProcess, INFINITE);
        g_terminalState.fatal("backend process died");
    });

    const int controlSocketC = acceptClientAndAuthenticate(controlSocket, key);
    const int dataSocketC = acceptClientAndAuthenticate(dataSocket, key);
    controlSocket.close();
    dataSocket.close();

    mainLoop(controlSocketC, dataSocketC, initialSize);
    return 0;
}
