#include "pch.h"
#include "httplib.h"

#pragma comment(lib, "Shlwapi.lib")

using namespace std;

const string WINSCP_UPDATE_PAGE_DOMAIN = "https://winscp.net";
const string WINSCP_UPDATE_PAGE_PATH = "/eng/downloads.php";
const string WINSCP_EXE_FILENAME = "WinSCP.exe";

HMODULE hRealVersionDll = NULL;

template<typename T>
T GetFunctionT(LPCSTR name) {
    return (T)GetProcAddress(hRealVersionDll, name);
}

template <typename FuncType, typename... Args>
auto ProxyFunction(FuncType realFunc, Args... args) -> decltype(realFunc(args...)) {
    if (realFunc) {
        return realFunc(args...);
    }

    SetLastError(ERROR_PROC_NOT_FOUND);

    return static_cast<decltype(realFunc(args...))>(0); // 返回默认值，例如 0 或 FALSE
}

// --- 定义你需要转发的 version.dll 函数指针类型 ---
typedef BOOL(WINAPI* VerQueryValueW_Type)(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen);
typedef BOOL(WINAPI* GetFileVersionInfoW_Type)(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
typedef DWORD(WINAPI* GetFileVersionInfoSizeW_Type)(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);

// --- 存储真实函数地址的指针 ---
VerQueryValueW_Type Real_VerQueryValueW = NULL;
GetFileVersionInfoW_Type Real_GetFileVersionInfoW = NULL;
GetFileVersionInfoSizeW_Type Real_GetFileVersionInfoSizeW = NULL;

BOOL LoadRealVersionDll() {
    CHAR realDllPath[MAX_PATH];

    // 获取 System32 目录路径
    if (!GetSystemDirectoryA(realDllPath, MAX_PATH)) {
        OutputDebugStringA("Failed to get system directory.\n");

        return FALSE;
    }

    // 拼接真实 version.dll 的完整路径
    PathCombineA(realDllPath, realDllPath, "version.dll");

    // 加载真实的 version.dll
    hRealVersionDll = LoadLibraryA(realDllPath);

    if (!hRealVersionDll) {
        OutputDebugStringA("Failed to load real version.dll.\n");

        return FALSE;
    }

    // 获取需要转发的函数地址
    Real_GetFileVersionInfoSizeW = GetFunctionT<GetFileVersionInfoSizeW_Type>("GetFileVersionInfoSizeW");
    Real_GetFileVersionInfoW = GetFunctionT<GetFileVersionInfoW_Type>("GetFileVersionInfoW");
    Real_VerQueryValueW = GetFunctionT<VerQueryValueW_Type>("VerQueryValueW");

    // 检查是否所有必要的函数都获取成功
    if (!Real_GetFileVersionInfoSizeW || !Real_GetFileVersionInfoW || !Real_VerQueryValueW) {
        OutputDebugStringA("Failed to get function pointers from real version.dll.\n");

        return FALSE;
    }

    return TRUE;
}

string file_get_contents(string domain, string path) {
    httplib::Client cli(domain);

    auto res = cli.Get(path);

    if (res && res->status == 200) {
        return res->body;
    }

    return "";
}

string getVersionNum(const string html) {
    if (html != "") {
        regex hrefRegex("/eng/docs/history\\?a=([^\"']+)\">List of all changes</a>"); // 获取版本号

        smatch match;

        if (regex_search(html, match, hrefRegex)) {
            return match[1];
        }
    }

    return "";
}

vector<int> GetFileVersion(const wstring filePath) {
    DWORD dwHandle = 0;
    DWORD dwSize = GetFileVersionInfoSize(filePath.c_str(), &dwHandle);

    if (dwSize == 0) {
        return { 0 };
    }

    BYTE* pVersionInfo = new BYTE[dwSize];
    vector<int> versions = { 0 };

    if (GetFileVersionInfo(filePath.c_str(), 0, dwSize, pVersionInfo)) {
        VS_FIXEDFILEINFO* pFileInfo = nullptr;
        UINT uLen = 0;

        if (VerQueryValue(pVersionInfo, L"\\", (LPVOID*)&pFileInfo, &uLen)) {
            versions = {
                (int)HIWORD(pFileInfo->dwFileVersionMS),
                (int)LOWORD(pFileInfo->dwFileVersionMS),
                (int)HIWORD(pFileInfo->dwFileVersionLS),
                (int)LOWORD(pFileInfo->dwFileVersionLS)
            };
        }
    }

    delete[] pVersionInfo;

    return versions;
}

vector<int> splitVersion(const string version) {
    vector<int> parts;
    stringstream ss(version);
    string part;

    while (getline(ss, part, '.')) {
        parts.push_back(stoi(part));
    }

    return parts;
}

int compareVersion(const vector<int> v1, const vector<int> v2) {
    size_t len = max(v1.size(), v2.size());

    vector<int> ver1 = v1, ver2 = v2;

    ver1.resize(len, 0);
    ver2.resize(len, 0);

    for (size_t i = 0; i < len; ++i) {
        if (ver1[i] < ver2[i]) return -1;
        if (ver1[i] > ver2[i]) return 1;
    }

    return 0;
}

void TriggerUpdateCheck() {
    string contents = file_get_contents(WINSCP_UPDATE_PAGE_DOMAIN, WINSCP_UPDATE_PAGE_PATH);

    string websiteVer = getVersionNum(contents);

    if (websiteVer != "") {
        MessageBoxA(NULL, websiteVer.c_str(), "", NULL);

        vector<int> localVersion = GetFileVersion(L"D:\\Program Files (x86)\\WinSCP\\WinSCP.exe"); // filesystem::current_path()

        vector<int> onlineVersion = splitVersion(websiteVer);

        int result = compareVersion(localVersion, onlineVersion);

        if (result < 0) {

        }

        return; // 未获取到数据直接返回
    }
}

DWORD WINAPI InitThread(LPVOID) {
    TriggerUpdateCheck(); // 触发更新检查

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // 禁止 DllMain 收到 DLL_THREAD_ATTACH 和 DLL_THREAD_DETACH 通知，可以轻微提高性能
            DisableThreadLibraryCalls(hModule);

            // 加载真实的 DLL 并获取函数指针
            if (!LoadRealVersionDll()) {
                // 加载失败，可以选择是否让进程失败
                MessageBoxA(NULL, "Failed to load real version.dll. Application might not work correctly.",
                            "Error", MB_OK | MB_ICONERROR);

                return FALSE; // 返回 FALSE 会导致加载 DLL 的进程失败
            }

            CreateThread(NULL, 0, InitThread, NULL, 0, NULL);

            break;
        // case DLL_THREAD_ATTACH:
            // 通常不需要处理
            // break;
        // case DLL_THREAD_DETACH:
            // 通常不需要处理
            // break;
        case DLL_PROCESS_DETACH:
            // 释放真实 DLL 的句柄
            if (hRealVersionDll) {
                FreeLibrary(hRealVersionDll);
                hRealVersionDll = NULL;
            }

            break;
    }

    return TRUE; // 必须返回 TRUE，除非你想让进程加载失败
}

// --- 导出并转发函数 ---
BOOL WINAPI Proxy_VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    return ProxyFunction(Real_VerQueryValueW, pBlock, lpSubBlock, lplpBuffer, puLen);
}

BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    return ProxyFunction(Real_GetFileVersionInfoW, lptstrFilename, dwHandle, dwLen, lpData);
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    return ProxyFunction(Real_GetFileVersionInfoSizeW, lptstrFilename, lpdwHandle);
}
