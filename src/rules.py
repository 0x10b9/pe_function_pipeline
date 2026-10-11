"""API prototypes and behaviour rules used by step 3 (argument extraction) and
step 4 (verification).

Rules are deliberately small and readable: they are a *verifier* for the
functions the model points at, not a detector on their own. Extend RULES and
PROTOTYPES for your own families.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Prototypes: argument names in call order (x64: rcx, rdx, r8, r9, then stack)
# --------------------------------------------------------------------------
PROTOTYPES: dict[str, list[str]] = {
    "RegOpenKeyEx": ["hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult"],
    "RegCreateKeyEx": ["hKey", "lpSubKey", "Reserved", "lpClass", "dwOptions", "samDesired",
                       "lpSecurityAttributes", "phkResult", "lpdwDisposition"],
    "RegSetValueEx": ["hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData"],
    "RegSetKeyValue": ["hKey", "lpSubKey", "lpValueName", "dwType", "lpData", "cbData"],
    "URLDownloadToFile": ["pCaller", "szURL", "szFileName", "dwReserved", "lpfnCB"],
    "WinExec": ["lpCmdLine", "uCmdShow"],
    "CreateProcess": ["lpApplicationName", "lpCommandLine", "lpProcessAttributes",
                      "lpThreadAttributes", "bInheritHandles", "dwCreationFlags",
                      "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo",
                      "lpProcessInformation"],
    "ShellExecute": ["hwnd", "lpOperation", "lpFile", "lpParameters", "lpDirectory", "nShowCmd"],
    "CreateRemoteThread": ["hProcess", "lpThreadAttributes", "dwStackSize", "lpStartAddress",
                           "lpParameter", "dwCreationFlags", "lpThreadId"],
    "WriteProcessMemory": ["hProcess", "lpBaseAddress", "lpBuffer", "nSize",
                           "lpNumberOfBytesWritten"],
    "VirtualAllocEx": ["hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"],
    "VirtualAlloc": ["lpAddress", "dwSize", "flAllocationType", "flProtect"],
    "VirtualProtect": ["lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"],
    "LoadLibrary": ["lpLibFileName"],
    "GetProcAddress": ["hModule", "lpProcName"],
    "CreateFile": ["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes",
                   "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"],
    "SetWindowsHookEx": ["idHook", "lpfn", "hmod", "dwThreadId"],
    "lstrlen": ["lpString"],
}

# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
LEVELS = {"no_evidence": 0, "weak": 1, "needs_review": 2, "suspicious": 3}


@dataclass
class ArgCheck:
    arg: str                 # argument name (from PROTOTYPES)
    pattern: str             # regex applied to the rendered argument text
    reason: str


@dataclass
class Rule:
    id: str
    category: str
    apis: set[str]
    severity: str                       # high | medium | low (used when there are no arg checks)
    checks: list[ArgCheck] = field(default_factory=list)
    cap: str = "suspicious"             # highest verdict this rule may produce on its own
    note: str = ""


RULES: list[Rule] = [
    Rule("persistence.autorun_registry", "persistence",
         {"RegOpenKeyEx", "RegCreateKeyEx", "RegSetKeyValue", "RegSetValueEx"}, "high",
         checks=[
             ArgCheck("lpSubKey", r"(?i)\\(CurrentVersion\\(Run|RunOnce|RunServices)|Winlogon|"
                                  r"Image File Execution Options)", "touches an autorun registry key"),
             ArgCheck("lpData", r"(?i)\\(Users\\Public|Temp|AppData)\\[^\\]*\.(exe|dll|bat|ps1|scr)",
                      "autorun target in a user-writable directory"),
         ]),
    Rule("download.remote_file", "download_execute",
         {"URLDownloadToFile", "URLDownloadToCacheFile"}, "high",
         checks=[
             ArgCheck("szURL", r"(?i)^(https?|ftp)://", "downloads from a remote URL"),
             ArgCheck("szFileName", r"(?i)\.(exe|dll|bin|scr|bat|ps1)$|\\(Users\\Public|Temp|AppData)",
                      "saves to disk in a user-writable / executable path"),
         ]),
    Rule("execution.scripting_or_lolbin", "execution",
         {"WinExec", "CreateProcess", "ShellExecute", "ShellExecuteEx"}, "medium",
         checks=[
             ArgCheck("lpCmdLine|lpCommandLine|lpFile|lpParameters",
                      r"(?i)(cmd(\.exe)?\s*/[ck]|powershell|wscript|cscript|mshta|rundll32|"
                      r"regsvr32|certutil|bitsadmin|vssadmin)",
                      "launches a shell / scripting engine / LOLBin command line"),
         ]),
    Rule("injection.remote_memory", "injection",
         {"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "NtWriteVirtualMemory",
          "QueueUserAPC", "SetThreadContext"}, "high",
         note="intrinsically high-risk API; confirm the target process and context"),
    Rule("evasion.rwx_memory", "evasion", {"VirtualProtect", "VirtualAlloc"}, "medium",
         checks=[ArgCheck("flNewProtect|flProtect", r"(?i)^0x40$", "requests PAGE_EXECUTE_READWRITE")],
         cap="needs_review",
         note="benign loaders and CRT start-up code also do this -> capped at needs_review"),
    Rule("collection.keyboard_hook", "collection", {"SetWindowsHookEx"}, "high",
         checks=[ArgCheck("idHook", r"^(0xd|13)$", "installs a low-level keyboard hook (WH_KEYBOARD_LL)")]),
    Rule("evasion.debugger_check", "anti_analysis",
         {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}, "medium"),
    Rule("evasion.dynamic_resolve", "evasion", {"GetProcAddress", "LoadLibrary"}, "low",
         note="very common in benign code; only informative together with other evidence"),
]


def normalize_api(name: str) -> str:
    """RegSetValueExA -> RegSetValueEx, but keep names that exist as-is."""
    known = set(PROTOTYPES) | {a for r in RULES for a in r.apis}
    if name in known:
        return name
    if name[-1:] in ("A", "W") and name[:-1] in known:
        return name[:-1]
    if name[-2:] in ("Ex",) and name[:-2] in known:
        return name[:-2]
    return name


def rules_for_api(api: str) -> list[Rule]:
    return [r for r in RULES if api in r.apis]


def compile_check(chk: ArgCheck):
    return re.compile(chk.pattern)
