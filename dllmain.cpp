// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

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
GetFileVersionInfoSizeW_Type Real_GetFileVersionInfoSizeW = NULL;
GetFileVersionInfoW_Type Real_GetFileVersionInfoW = NULL;
VerQueryValueW_Type Real_VerQueryValueW = NULL;

BOOL LoadRealVersionDll() {
    WCHAR realDllPath[MAX_PATH];

    // 获取 System32 目录路径
    if (!GetSystemDirectoryW(realDllPath, MAX_PATH)) {
        OutputDebugStringW(L"ProxyDLL: Failed to get system directory.\n");

        return FALSE;
    }

    // 拼接真实 version.dll 的完整路径
    PathCombineW(realDllPath, realDllPath, L"version.dll");

    // 加载真实的 version.dll
    hRealVersionDll = LoadLibraryW(realDllPath);

    if (!hRealVersionDll) {
        OutputDebugStringW(L"ProxyDLL: Failed to load real version.dll.\n");

        return FALSE;
    }

    // 获取需要转发的函数地址
    Real_GetFileVersionInfoSizeW = GetFunctionT<GetFileVersionInfoSizeW_Type>("GetFileVersionInfoSizeW");
    Real_GetFileVersionInfoW = GetFunctionT<GetFileVersionInfoW_Type>("GetFileVersionInfoW");
    Real_VerQueryValueW = GetFunctionT<VerQueryValueW_Type>("VerQueryValueW");

    // 检查是否所有必要的函数都获取成功（根据实际需要添加检查）
    if (!Real_GetFileVersionInfoSizeW || !Real_GetFileVersionInfoW || !Real_VerQueryValueW) {
        OutputDebugStringW(L"ProxyDLL: Failed to get one or more function pointers from real version.dll.\n");

        return FALSE; // 如果缺少关键函数则失败
    }

    OutputDebugStringW(L"ProxyDLL: Real version.dll loaded and function pointers obtained.\n");

    return TRUE;
}

void TriggerUpdateCheck() {
    MessageBoxW(0, L"测试消息", L"", 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            OutputDebugStringW(L"ProxyDLL: DLL_PROCESS_ATTACH\n");

            // 禁止 DllMain 收到 DLL_THREAD_ATTACH 和 DLL_THREAD_DETACH 通知，可以轻微提高性能
            DisableThreadLibraryCalls(hModule);

            // 加载真实的 DLL 并获取函数指针
            if (!LoadRealVersionDll()) {
                // 加载失败，可以选择是否让进程失败
                MessageBoxW(NULL, L"Failed to load real version.dll. Application might not work correctly.",
                            L"Proxy DLL Error", MB_OK | MB_ICONERROR);
                return FALSE; // 返回 FALSE 会导致加载 DLL 的进程失败
            }

            TriggerUpdateCheck(); // 触发更新检查
            break;
        case DLL_THREAD_ATTACH:
            // 通常不需要处理
            break;
        case DLL_THREAD_DETACH:
            // 通常不需要处理
            break;
        case DLL_PROCESS_DETACH:
            OutputDebugStringW(L"ProxyDLL: DLL_PROCESS_DETACH\n");

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
