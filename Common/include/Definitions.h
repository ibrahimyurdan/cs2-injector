#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

// Export/Import definitions
#ifdef LIBRARY_EXPORTS
#define API_EXPORT __declspec(dllexport)
#else
#define API_EXPORT __declspec(dllimport)
#endif

// Function calling conventions
#define WINAPI_CALL __stdcall
#define CDECL_CALL __cdecl

// Version information
#define CS2INJECTOR_VERSION_MAJOR 1
#define CS2INJECTOR_VERSION_MINOR 0
#define CS2INJECTOR_VERSION_PATCH 0
#define CS2INJECTOR_VERSION_STR "1.0.0"

// Default values
#define DEFAULT_PROCESS_NAME L"cs2.exe"
#define DEFAULT_DLL_NAME L"payload.dll"
#define DEFAULT_CONFIG_FILE L"CS2Injector.ini"
#define DEFAULT_SILENT_MODE 0
#define DEFAULT_CLOSE_DELAY 3000

// Error codes
enum class InjectionError {
    SUCCESS = 0,
    PROCESS_NOT_FOUND = 1,
    CANNOT_OPEN_PROCESS = 2,
    CANNOT_ALLOCATE_MEMORY = 3,
    CANNOT_WRITE_MEMORY = 4,
    CANNOT_CREATE_THREAD = 5,
    CANNOT_GET_MODULE_HANDLE = 6,
    CANNOT_GET_PROC_ADDRESS = 7,
    CANNOT_LOAD_DLL = 8,
    CANNOT_MAP_DLL = 9,
    THREAD_HIJACK_FAILED = 10,
    CANNOT_READ_PE_HEADERS = 11,
    INVALID_PE_SIGNATURE = 12,
    INVALID_PE_ARCHITECTURE = 13,
    GENERAL_ERROR = 100
};

// Injection methods
enum class InjectionMethod {
    LOAD_LIBRARY = 0,        // Traditional LoadLibrary injection
    MANUAL_MAP = 1,          // Manual mapping with PE parsing
    THREAD_HIJACK = 2,       // Thread hijacking approach
    SHELLCODE_INJECT = 3     // Custom shellcode injection
};

// Structure for process information
struct ProcessInfo {
    DWORD id;
    std::wstring name;
    HANDLE handle;
    BOOL is64Bit;
    std::wstring path;
};

// Structure for module information
struct ModuleInfo {
    HMODULE handle;
    std::wstring name;
    PVOID baseAddress;
    SIZE_T imageSize;
    std::wstring path;
};

// Structure for injection options
struct InjectionOptions {
    std::wstring targetProcess;
    std::wstring dllPath;
    InjectionMethod method;
    bool useRandomization;
    bool cleanupPEHeaders;
    bool useEvasionTechniques;
    bool waitForExit;
    DWORD timeout;
};

// Callback function types
using InjectionCallback = std::function<void(InjectionError, const std::wstring&)>;
using LogCallback = std::function<void(const std::wstring&)>;

// Macro for error checking
#define CHECK_ERROR(expr, error_code, error_msg) \
    if (!(expr)) { \
        if (logCallback) logCallback(error_msg); \
        return error_code; \
    }

// Function to convert error code to string
inline std::wstring GetErrorString(InjectionError error) {
    switch (error) {
    case InjectionError::SUCCESS:
        return L"Success";
    case InjectionError::PROCESS_NOT_FOUND:
        return L"Process not found";
    case InjectionError::CANNOT_OPEN_PROCESS:
        return L"Cannot open process";
    case InjectionError::CANNOT_ALLOCATE_MEMORY:
        return L"Cannot allocate memory in target process";
    case InjectionError::CANNOT_WRITE_MEMORY:
        return L"Cannot write to target process memory";
    case InjectionError::CANNOT_CREATE_THREAD:
        return L"Cannot create remote thread";
    case InjectionError::CANNOT_GET_MODULE_HANDLE:
        return L"Cannot get module handle";
    case InjectionError::CANNOT_GET_PROC_ADDRESS:
        return L"Cannot get procedure address";
    case InjectionError::CANNOT_LOAD_DLL:
        return L"Cannot load DLL";
    case InjectionError::CANNOT_MAP_DLL:
        return L"Cannot map DLL into target process";
    case InjectionError::THREAD_HIJACK_FAILED:
        return L"Thread hijacking failed";
    case InjectionError::CANNOT_READ_PE_HEADERS:
        return L"Cannot read PE headers";
    case InjectionError::INVALID_PE_SIGNATURE:
        return L"Invalid PE signature";
    case InjectionError::INVALID_PE_ARCHITECTURE:
        return L"Invalid PE architecture (32-bit DLL for 64-bit process or vice versa)";
    case InjectionError::GENERAL_ERROR:
    default:
        return L"General error";
    }
} 