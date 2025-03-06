#pragma once

#include "Definitions.h"

namespace CS2Injector {

class API_EXPORT Injector {
public:
    // Constructor and destructor
    Injector();
    ~Injector();

    // Initialize the injector with options
    InjectionError Initialize(const InjectionOptions& options, LogCallback logCallback = nullptr);

    // Set a callback function to receive injection status updates
    void SetCallback(InjectionCallback callback);

    // Main injection function
    InjectionError Inject();

    // Get the last error message
    std::wstring GetLastErrorMessage() const;

    // Get injector version
    static std::wstring GetVersion();

    // Static utility methods for process manipulation
    static std::vector<ProcessInfo> GetProcessList();
    static ProcessInfo GetProcessByName(const std::wstring& processName);
    static bool IsProcessRunning(const std::wstring& processName);
    static bool Is64BitProcess(HANDLE processHandle);

private:
    // Internal implementation methods
    InjectionError InjectViaLoadLibrary();
    InjectionError InjectViaManualMap();
    InjectionError InjectViaThreadHijack();
    InjectionError InjectViaShellcode();

    // Memory handling methods
    PVOID AllocateMemoryInTarget(SIZE_T size);
    bool WriteMemoryToTarget(PVOID targetAddress, LPCVOID data, SIZE_T size);
    bool ReadMemoryFromTarget(PVOID targetAddress, LPVOID buffer, SIZE_T size);
    bool FreeMemoryInTarget(PVOID address);

    // Process and module handling
    HANDLE OpenTargetProcess();
    HMODULE GetRemoteModuleHandle(const std::wstring& moduleName);
    FARPROC GetRemoteProcAddress(HMODULE module, const char* procName);
    
    // Thread manipulation
    HANDLE CreateRemoteThread(LPVOID startAddress, LPVOID parameter);
    bool SuspendThread(HANDLE thread);
    bool ResumeThread(HANDLE thread);
    bool WaitForThreadToExit(HANDLE thread, DWORD timeout);
    
    // Hijacking methods
    HANDLE FindSuitableThreadForHijacking();
    bool SaveThreadContext(HANDLE thread, CONTEXT& context);
    bool RestoreThreadContext(HANDLE thread, const CONTEXT& context);
    bool HijackThread(HANDLE thread, LPVOID startAddress, LPVOID parameter);

    // VAC evasion techniques
    void ApplyEvasionTechniques();
    void ObfuscateMemoryWrites();
    void RandomizeMemoryAllocation();
    void CleanupPEHeaders(PVOID baseAddress);
    
    // PE mapping functions
    bool MapPEHeaders(PVOID targetBase, LPVOID sourceData);
    bool MapPESections(PVOID targetBase, LPVOID sourceData);
    bool ResolveImports(PVOID targetBase);
    bool RelocateImage(PVOID targetBase, uintptr_t delta);
    bool ExecuteTLSCallbacks(PVOID targetBase);
    bool CallEntryPoint(PVOID targetBase);

    // Private members
    InjectionOptions options_;
    ProcessInfo targetProcess_;
    std::wstring lastErrorMessage_;
    InjectionCallback callback_;
    LogCallback logCallback_;
    bool initialized_;
};

} // namespace CS2Injector 