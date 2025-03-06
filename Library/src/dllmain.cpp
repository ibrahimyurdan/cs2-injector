#include <Windows.h>
#include "Injector.h"
#include "Definitions.h"
#include "Utilities.h"

using namespace CS2Injector;

// Global injector instance
static Injector* g_pInjector = nullptr;
static Utilities::Logger* g_pLogger = nullptr;

// Function to log messages
void LogMessage(const std::wstring& message) {
    if (g_pLogger) {
        g_pLogger->Info(message);
    }
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Initialize the logger
        g_pLogger = new Utilities::Logger(Utilities::CombinePath(
            Utilities::GetModuleDirectory(hModule), L"CS2Injector.log"));
        g_pLogger->SetLogLevel(Utilities::Logger::LogLevel::INFO);
        
        // Initialize the injector
        g_pInjector = new Injector();
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
        
    case DLL_PROCESS_DETACH:
        // Clean up
        if (g_pInjector) {
            delete g_pInjector;
            g_pInjector = nullptr;
        }
        
        if (g_pLogger) {
            g_pLogger->Info(L"CS2Injector DLL detached");
            delete g_pLogger;
            g_pLogger = nullptr;
        }
        break;
    }
    return TRUE;
}

// Export functions

// Initialize the injector with options
extern "C" API_EXPORT InjectionError WINAPI_CALL Initialize(const InjectionOptions* pOptions) {
    if (!g_pInjector) {
        return InjectionError::GENERAL_ERROR;
    }
    
    return g_pInjector->Initialize(*pOptions, LogMessage);
}

// Inject DLL into the target process
extern "C" API_EXPORT InjectionError WINAPI_CALL Inject() {
    if (!g_pInjector) {
        return InjectionError::GENERAL_ERROR;
    }
    
    return g_pInjector->Inject();
}

// Set callback function
extern "C" API_EXPORT void WINAPI_CALL SetCallback(InjectionCallback callback) {
    if (g_pInjector) {
        g_pInjector->SetCallback(callback);
    }
}

// Get the last error message
extern "C" API_EXPORT const wchar_t* WINAPI_CALL GetLastErrorMessage() {
    if (!g_pInjector) {
        return L"Injector not initialized";
    }
    
    static std::wstring lastError;
    lastError = g_pInjector->GetLastErrorMessage();
    return lastError.c_str();
}

// Check if a process is running
extern "C" API_EXPORT BOOL WINAPI_CALL IsProcessRunning(const wchar_t* processName) {
    return Injector::IsProcessRunning(processName) ? TRUE : FALSE;
}

// Get the injector version
extern "C" API_EXPORT const wchar_t* WINAPI_CALL GetVersion() {
    static std::wstring version = Injector::GetVersion();
    return version.c_str();
}

// Simplified injection with all parameters
extern "C" API_EXPORT InjectionError WINAPI_CALL InjectDLL(
    const wchar_t* processName, 
    const wchar_t* dllPath, 
    InjectionMethod method, 
    BOOL useRandomization, 
    BOOL cleanupPEHeaders, 
    BOOL useEvasionTechniques
) {
    if (!g_pInjector) {
        g_pInjector = new Injector();
    }
    
    InjectionOptions options;
    options.targetProcess = processName;
    options.dllPath = dllPath;
    options.method = method;
    options.useRandomization = useRandomization != FALSE;
    options.cleanupPEHeaders = cleanupPEHeaders != FALSE;
    options.useEvasionTechniques = useEvasionTechniques != FALSE;
    options.waitForExit = FALSE;
    options.timeout = 10000; // 10 seconds
    
    InjectionError result = g_pInjector->Initialize(options, LogMessage);
    if (result != InjectionError::SUCCESS) {
        return result;
    }
    
    return g_pInjector->Inject();
}

// Get a list of all processes
extern "C" API_EXPORT BOOL WINAPI_CALL GetProcessList(
    ProcessInfo* processes, 
    DWORD* count
) {
    if (!count) {
        return FALSE;
    }
    
    std::vector<ProcessInfo> processList = Injector::GetProcessList();
    
    if (!processes) {
        *count = static_cast<DWORD>(processList.size());
        return TRUE;
    }
    
    DWORD copyCount = min(*count, static_cast<DWORD>(processList.size()));
    for (DWORD i = 0; i < copyCount; i++) {
        processes[i] = processList[i];
    }
    
    *count = copyCount;
    return TRUE;
}

// Get a process by name
extern "C" API_EXPORT BOOL WINAPI_CALL GetProcessByName(
    const wchar_t* processName, 
    ProcessInfo* processInfo
) {
    if (!processName || !processInfo) {
        return FALSE;
    }
    
    *processInfo = Injector::GetProcessByName(processName);
    return processInfo->id != 0;
} 