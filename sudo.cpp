#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <sddl.h>
#include <userenv.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "userenv.lib")

/* ============================================================
   全局状态
   ============================================================ */
static wchar_t g_username[256];
static wchar_t g_cacheFile[MAX_PATH];
static time_t  g_cacheExpiry = 0;
static BOOL    g_hasCache = FALSE;

/* ============================================================
   辅助函数
   ============================================================ */
static void PrintError(const wchar_t* prefix) {
    DWORD err = GetLastError();
    wchar_t* msg = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, err, 0, (wchar_t*)&msg, 0, NULL);
    if (msg) {
        fwprintf(stderr, L"%s: %s", prefix, msg);
        LocalFree(msg);
    } else {
        fwprintf(stderr, L"%s: error %lu\n", prefix, err);
    }
}

static void PrintUsage(const wchar_t* prog) {
    fwprintf(stderr, L"usage: %s command [arg1 arg2 ...]\n", prog);
}

static BOOL IsUserAdmin(void) {
    BOOL b = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &b);
        FreeSid(AdministratorsGroup);
    }
    return b;
}

static BOOL EnablePrivilege(const wchar_t* name) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

/* ============================================================
   密码缓存（5分钟）
   ============================================================ */
static void GetCachePath(void) {
    wchar_t path[MAX_PATH];
    GetEnvironmentVariableW(L"LOCALAPPDATA", path, MAX_PATH);
    wsprintfW(g_cacheFile, L"%s\\.sudo_cache", path);
}

static void LoadCache(void) {
    GetCachePath();
    FILE* f = _wfopen(g_cacheFile, L"rb");
    if (!f) return;
    wchar_t user[256];
    time_t expiry;
    if (fwscanf(f, L"%255s %lld", user, &expiry) == 2) {
        if (wcscmp(user, g_username) == 0 && time(NULL) < expiry) {
            g_cacheExpiry = expiry;
            g_hasCache = TRUE;
        }
    }
    fclose(f);
}

static void SaveCache(void) {
    GetCachePath();
    FILE* f = _wfopen(g_cacheFile, L"wb");
    if (f) {
        g_cacheExpiry = time(NULL) + 300; // 5分钟
        fwprintf(f, L"%s %lld\n", g_username, g_cacheExpiry);
        fclose(f);
        g_hasCache = TRUE;
    }
}

static void ClearCache(void) {
    GetCachePath();
    _wremove(g_cacheFile);
    g_hasCache = FALSE;
    g_cacheExpiry = 0;
}

/* ============================================================
   密码验证（3次尝试，完全还原 Linux sudo）
   ============================================================ */
static BOOL VerifyPassword(void) {
    LoadCache();
    if (g_hasCache && time(NULL) < g_cacheExpiry) {
        SaveCache(); // 重新计时5分钟
        return TRUE;
    }

    DWORD len = 256;
    GetUserNameW(g_username, &len);

    for (int attempt = 1; attempt <= 3; attempt++) {
        fwprintf(stderr, L"[sudo] password for %s: ", g_username);
        
        // 隐藏输入
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

        wchar_t pass[256];
        if (!fgetws(pass, 256, stdin)) {
            SetConsoleMode(hStdin, mode);
            fputwc(L'\n', stderr);
            continue;
        }
        SetConsoleMode(hStdin, mode);
        fputwc(L'\n', stderr);

        // 去掉换行
        size_t plen = wcslen(pass);
        if (plen > 0 && pass[plen-1] == L'\n') pass[plen-1] = L'\0';
        if (plen > 1 && pass[plen-2] == L'\r') pass[plen-2] = L'\0';

        // 验证密码
        HANDLE hToken;
        if (LogonUserW(g_username, L".", pass, LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT, &hToken)) {
            CloseHandle(hToken);
            SecureZeroMemory(pass, sizeof(pass));
            SaveCache();
            return TRUE;
        }
        SecureZeroMemory(pass, sizeof(pass));

        if (attempt < 3) {
            fwprintf(stderr, L"Sorry, try again.\n");
        }
    }

    fwprintf(stderr, L"sudo: 3 incorrect password attempts\n");
    return FALSE;
}

/* ============================================================
   Token 操作
   ============================================================ */
static HANDLE GetProcessToken(DWORD pid, DWORD access) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (!hProcess) return NULL;

    HANDLE hToken = NULL;
    OpenProcessToken(hProcess, access, &hToken);
    CloseHandle(hProcess);
    return hToken;
}

static HANDLE DuplicateElevatedToken(HANDLE hToken) {
    HANDLE hDup = NULL;
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
        TokenPrimary, &hDup);
    return hDup;
}

/* ============================================================
   获取 SYSTEM Token（从 winlogon 或 csrss）
   ============================================================ */
static HANDLE GetSystemToken(void) {
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        return NULL;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    HANDLE hToken = NULL;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            // 优先找 winlogon.exe（最稳定）
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                HANDLE hTemp = GetProcessToken(pe.th32ProcessID, TOKEN_DUPLICATE | TOKEN_QUERY);
                if (hTemp) {
                    // 确认是 SYSTEM
                    DWORD needed = 0;
                    GetTokenInformation(hTemp, TokenUser, NULL, 0, &needed);
                    if (needed > 0) {
                        PTOKEN_USER tu = (PTOKEN_USER)malloc(needed);
                        if (tu && GetTokenInformation(hTemp, TokenUser, tu, needed, &needed)) {
                            SID_NAME_USE use;
                            wchar_t name[256], dom[256];
                            DWORD nl = 256, dl = 256;
                            if (LookupAccountSidW(NULL, tu->User.Sid, name, &nl, dom, &dl, &use)) {
                                if (_wcsicmp(name, L"SYSTEM") == 0) {
                                    hToken = DuplicateElevatedToken(hTemp);
                                }
                            }
                        }
                        free(tu);
                    }
                    CloseHandle(hTemp);
                    if (hToken) break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }

    // 备选：找 csrss.exe
    if (!hToken) {
        Process32FirstW(hSnap, &pe);
        do {
            if (_wcsicmp(pe.szExeFile, L"csrss.exe") == 0) {
                HANDLE hTemp = GetProcessToken(pe.th32ProcessID, TOKEN_DUPLICATE | TOKEN_QUERY);
                if (hTemp) {
                    hToken = DuplicateElevatedToken(hTemp);
                    CloseHandle(hTemp);
                    if (hToken) break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return hToken;
}

/* ============================================================
   获取 TrustedInstaller Token
   ============================================================ */
static HANDLE GetTrustedInstallerToken(void) {
    // 启动 TrustedInstaller 服务
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return NULL;

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return NULL;
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(hSvc, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            StartServiceW(hSvc, 0, NULL);
            // 等待启动
            for (int i = 0; i < 50; i++) {
                Sleep(100);
                QueryServiceStatus(hSvc, &status);
                if (status.dwCurrentState == SERVICE_RUNNING) break;
            }
        }
    }

    // 查找 TrustedInstaller.exe 进程
    DWORD tiPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"TrustedInstaller.exe") == 0) {
                    tiPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    if (!tiPid) return NULL;

    if (!EnablePrivilege(SE_DEBUG_NAME)) return NULL;

    HANDLE hToken = GetProcessToken(tiPid, TOKEN_DUPLICATE | TOKEN_QUERY);
    if (!hToken) return NULL;

    HANDLE hDup = DuplicateElevatedToken(hToken);
    CloseHandle(hToken);
    return hDup;
}

/* ============================================================
   执行命令
   ============================================================ */
static BOOL RunWithToken(HANDLE hToken, wchar_t* cmdline) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 加载用户环境
    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hToken, FALSE);

    BOOL ok = CreateProcessAsUserW(hToken, NULL, cmdline, NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, pEnv, NULL, &si, &pi);

    if (pEnv) DestroyEnvironmentBlock(pEnv);

    if (ok) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    return ok;
}

/* ============================================================
   清除微软官方 sudo for Windows
   ============================================================ */
static void RemoveMicrosoftSudo(void) {
    wchar_t path[MAX_PATH];
    BOOL removed = FALSE;

    GetSystemDirectoryW(path, MAX_PATH);
    wcscat(path, L"\\sudo.exe");
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        if (DeleteFileW(path)) {
            fwprintf(stderr, L"sudo: 已移除微软官方 sudo (System32)\n");
            removed = TRUE;
        } else {
            wchar_t bak[MAX_PATH];
            wsprintfW(bak, L"%s.sudo.bak", path);
            if (MoveFileExW(path, bak, MOVEFILE_REPLACE_EXISTING)) {
                fwprintf(stderr, L"sudo: 已禁用微软官方 sudo (System32) -> .sudo.bak\n");
                removed = TRUE;
            }
        }
    }

    GetWindowsDirectoryW(path, MAX_PATH);
    wcscat(path, L"\\SysWOW64\\sudo.exe");
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        if (DeleteFileW(path)) {
            fwprintf(stderr, L"sudo: 已移除微软官方 sudo (SysWOW64)\n");
            removed = TRUE;
        } else {
            wchar_t bak[MAX_PATH];
            wsprintfW(bak, L"%s.sudo.bak", path);
            if (MoveFileExW(path, bak, MOVEFILE_REPLACE_EXISTING)) {
                fwprintf(stderr, L"sudo: 已禁用微软官方 sudo (SysWOW64) -> .sudo.bak\n");
                removed = TRUE;
            }
        }
    }

    wchar_t localAppData[MAX_PATH];
    GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    wsprintfW(path, L"%s\\Microsoft\\WindowsApps\\sudo.exe", localAppData);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        if (DeleteFileW(path)) {
            fwprintf(stderr, L"sudo: 已移除微软官方 sudo (WindowsApps)\n");
            removed = TRUE;
        } else {
            wchar_t bak[MAX_PATH];
            wsprintfW(bak, L"%s.sudo.bak", path);
            if (MoveFileExW(path, bak, MOVEFILE_REPLACE_EXISTING)) {
                fwprintf(stderr, L"sudo: 已禁用微软官方 sudo (WindowsApps) -> .sudo.bak\n");
                removed = TRUE;
            }
        }
    }

    if (removed) {
        fwprintf(stderr, L"sudo: 微软官方 sudo 已清理完毕，本版本现在独占 PATH。\n");
    }
}

/* ============================================================
   从 PATH 中移除包含微软 sudo 的路径条目
   ============================================================ */
static void PurgeMicrosoftSudoFromPath(void) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return;

    wchar_t path[8192];
    DWORD size = sizeof(path);
    DWORD type;
    if (RegQueryValueExW(hKey, L"Path", NULL, &type, (BYTE*)path, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return;
    }

    const wchar_t* badPatterns[] = {
        L"WindowsApps",
        NULL
    };

    wchar_t newPath[8192] = L"";
    wchar_t* ctx = NULL;
    wchar_t* token = wcstok_s(path, L";", &ctx);
    BOOL modified = FALSE;

    while (token) {
        BOOL keep = TRUE;
        for (int i = 0; badPatterns[i]; i++) {
            if (wcsstr(token, badPatterns[i])) {
                wchar_t testPath[MAX_PATH];
                wsprintfW(testPath, L"%s\\sudo.exe", token);
                if (GetFileAttributesW(testPath) != INVALID_FILE_ATTRIBUTES) {
                    keep = FALSE;
                    modified = TRUE;
                    break;
                }
            }
        }
        if (keep) {
            if (newPath[0]) wcscat(newPath, L";");
            wcscat(newPath, token);
        }
        token = wcstok_s(NULL, L";", &ctx);
    }

    if (modified) {
        RegSetValueExW(hKey, L"Path", 0, REG_EXPAND_SZ, (BYTE*)newPath, (wcslen(newPath)+1)*2);
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment",
            SMTO_ABORTIFHUNG, 5000, NULL);
        fwprintf(stderr, L"sudo: 已从用户 PATH 中移除微软 sudo 相关条目。\n");
    }

    RegCloseKey(hKey);
}

/* ============================================================
   自安装到 System32
   ============================================================ */
static BOOL IsInSystem32(void) {
    wchar_t self[MAX_PATH], sys32[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    GetSystemDirectoryW(sys32, MAX_PATH);
    size_t sl = wcslen(sys32);
    return (wcsnicmp(self, sys32, sl) == 0);
}

static BOOL SelfInstall(void) {
    if (IsInSystem32()) {
        RemoveMicrosoftSudo();
        return TRUE;
    }

    if (!IsUserAdmin()) {
        fwprintf(stderr, L"sudo: 首次安装需要管理员权限。请以管理员身份运行一次。\n");
        return FALSE;
    }

    RemoveMicrosoftSudo();

    wchar_t self[MAX_PATH], dest[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    GetSystemDirectoryW(dest, MAX_PATH);
    wcscat(dest, L"\\sudo.exe");

    if (!CopyFileW(self, dest, FALSE)) {
        PrintError(L"sudo: 复制到 System32 失败");
        return FALSE;
    }

    PurgeMicrosoftSudoFromPath();

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        wchar_t path[8192];
        DWORD size = sizeof(path);
        DWORD type;
        if (RegQueryValueExW(hKey, L"Path", NULL, &type, (BYTE*)path, &size) == ERROR_SUCCESS) {
            GetSystemDirectoryW(dest, MAX_PATH);
            
            wchar_t* pos = wcsstr(path, dest);
            if (pos) {
                wchar_t newPath[8192] = L"";
                wchar_t* ctx = NULL;
                wchar_t* token = wcstok_s(path, L";", &ctx);
                while (token) {
                    if (wcsicmp(token, dest) != 0) {
                        if (newPath[0]) wcscat(newPath, L";");
                        wcscat(newPath, token);
                    }
                    token = wcstok_s(NULL, L";", &ctx);
                }
                wcscpy(path, newPath);
            }

            wchar_t finalPath[8192];
            wsprintfW(finalPath, L"%s;%s", dest, path);
            RegSetValueExW(hKey, L"Path", 0, REG_EXPAND_SZ, (BYTE*)finalPath, (wcslen(finalPath)+1)*2);
            
            SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment",
                SMTO_ABORTIFHUNG, 5000, NULL);
        }
        RegCloseKey(hKey);
    }

    fwprintf(stderr, L"sudo: 已安装到 System32 并置顶 PATH，现在可以在任意位置使用 sudo 命令。\n");
    return TRUE;
}

/* ============================================================
   主函数
   ============================================================ */
int wmain(int argc, wchar_t* argv[]) {
    if (!SelfInstall()) {
        return 1;
    }

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    int cmdLen = 0;
    for (int i = 1; i < argc; i++) {
        cmdLen += (int)wcslen(argv[i]) + 3;
    }
    wchar_t* cmdline = (wchar_t*)malloc(cmdLen * sizeof(wchar_t));
    cmdline[0] = L'\0';
    for (int i = 1; i < argc; i++) {
        if (i > 1) wcscat(cmdline, L" ");
        if (wcschr(argv[i], L' ')) {
            wcscat(cmdline, L"\"");
            wcscat(cmdline, argv[i]);
            wcscat(cmdline, L"\"");
        } else {
            wcscat(cmdline, argv[i]);
        }
    }

    if (!VerifyPassword()) {
        free(cmdline);
        return 1;
    }

    HANDLE hToken = GetSystemToken();
    BOOL ok = FALSE;

    if (hToken) {
        ok = RunWithToken(hToken, cmdline);
        if (!ok && GetLastError() == ERROR_ACCESS_DENIED) {
            CloseHandle(hToken);
            hToken = NULL;
        } else if (!ok) {
            CloseHandle(hToken);
            hToken = NULL;
        }
    }

    if (!ok) {
        hToken = GetTrustedInstallerToken();
        if (hToken) {
            ok = RunWithToken(hToken, cmdline);
            CloseHandle(hToken);
        }
    }

    if (!ok) {
        PrintError(L"sudo");
        free(cmdline);
        return 1;
    }

    free(cmdline);
    return 0;
}
