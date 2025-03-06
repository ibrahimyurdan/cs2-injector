#pragma once

#include "Definitions.h"
#include <TlHelp32.h>

namespace CS2Injector {

// Process access rights
enum class ProcessAccess {
    ALL_ACCESS = PROCESS_ALL_ACCESS,
    CREATE_PROCESS = PROCESS_CREATE_PROCESS,
    CREATE_THREAD = PROCESS_CREATE_THREAD,
    DUP_HANDLE = PROCESS_DUP_HANDLE,
    QUERY_INFORMATION = PROCESS_QUERY_INFORMATION,
    QUERY_LIMITED_INFORMATION = PROCESS_QUERY_LIMITED_INFORMATION,
    SET_INFORMATION = PROCESS_SET_INFORMATION,
    SET_QUOTA = PROCESS_SET_QUOTA,
    SUSPEND_RESUME = PROCESS_SUSPEND_RESUME,
    TERMINATE = PROCESS_TERMINATE,
    VM_OPERATION = PROCESS_VM_OPERATION,
    VM_READ = PROCESS_VM_READ,
    VM_WRITE = PROCESS_VM_WRITE
};

// Thread access rights
enum class ThreadAccess {
    ALL_ACCESS = THREAD_ALL_ACCESS,
    DIRECT_IMPERSONATION = THREAD_DIRECT_IMPERSONATION,
    GET_CONTEXT = THREAD_GET_CONTEXT,
    IMPERSONATE = THREAD_IMPERSONATE,
    QUERY_INFORMATION = THREAD_QUERY_INFORMATION,
    QUERY_LIMITED_INFORMATION = THREAD_QUERY_LIMITED_INFORMATION,
    SET_CONTEXT = THREAD_SET_CONTEXT,
    SET_INFORMATION = THREAD_SET_INFORMATION,
    SET_LIMITED_INFORMATION = THREAD_SET_LIMITED_INFORMATION,
    SET_THREAD_TOKEN = THREAD_SET_THREAD_TOKEN,
    SUSPEND_RESUME = THREAD_SUSPEND_RESUME,
    TERMINATE = THREAD_TERMINATE
};

class API_EXPORT ProcessManager {
public:
    // Constructor
    ProcessManager();
    
    // Destructor
    ~ProcessManager();
    
    // Get list of all processes
    std::vector<ProcessInfo> GetProcessList();
    
    // Get a process by name
    ProcessInfo GetProcessByName(const std::wstring& processName);
    
    // Get a process by ID
    ProcessInfo GetProcessById(DWORD processId);
    
    // Check if a process is running
    bool IsProcessRunning(const std::wstring& processName);
    bool IsProcessRunning(DWORD processId);
    
    // Open a process with specified access rights
    HANDLE OpenProcess(const std::wstring& processName, ProcessAccess access = ProcessAccess::ALL_ACCESS);
    HANDLE OpenProcess(DWORD processId, ProcessAccess access = ProcessAccess::ALL_ACCESS);
    
    // Close a process handle
    void CloseProcess(HANDLE& handle);
    
    // Get the process path from a handle
    std::wstring GetProcessPath(HANDLE processHandle);
    
    // Check if a process is 64-bit
    bool Is64BitProcess(HANDLE processHandle);
    
    // Get modules loaded in a process
    std::vector<ModuleInfo> GetProcessModules(HANDLE processHandle);
    
    // Get a module by name
    ModuleInfo GetModuleByName(HANDLE processHandle, const std::wstring& moduleName);
    
    // Check if a module is loaded
    bool IsModuleLoaded(HANDLE processHandle, const std::wstring& moduleName);
    
    // Get the base address of a module
    PVOID GetModuleBaseAddress(HANDLE processHandle, const std::wstring& moduleName);
    
    // Get all threads in a process
    std::vector<DWORD> GetProcessThreads(DWORD processId);
    
    // Open a thread with specified access rights
    HANDLE OpenThread(DWORD threadId, ThreadAccess access = ThreadAccess::ALL_ACCESS);
    
    // Close a thread handle
    void CloseThread(HANDLE& handle);
    
    // Suspend a process (all threads)
    bool SuspendProcess(DWORD processId);
    
    // Resume a process (all threads)
    bool ResumeProcess(DWORD processId);
    
    // Terminate a process
    bool TerminateProcess(DWORD processId, UINT exitCode = 0);
    
    // Wait for a process to exit
    bool WaitForProcessExit(DWORD processId, DWORD timeout = INFINITE);
    
    // Create a new process
    HANDLE CreateProcess(const std::wstring& applicationPath, const std::wstring& commandLine = L"", 
                        bool suspended = false, DWORD* processId = nullptr);
    
    // Inject a DLL into a process
    bool InjectDLL(HANDLE processHandle, const std::wstring& dllPath);
    
    // Eject a DLL from a process
    bool EjectDLL(HANDLE processHandle, const std::wstring& dllName);
    
    // Enable debug privileges for the current process
    bool EnableDebugPrivilege();
    
    // Get the process integrity level
    DWORD GetProcessIntegrityLevel(HANDLE processHandle);
    
    // Get the process DEP policy
    bool GetProcessDEPPolicy(HANDLE processHandle, BOOL* permanentDEP, BOOL* ATLThunkEmulation);
    
    // Set the process DEP policy
    bool SetProcessDEPPolicy(HANDLE processHandle, DWORD flags);
    
    // Check if the process is being debugged
    bool IsBeingDebugged(HANDLE processHandle);
    
    // Hide the process from the process list
    bool HideProcess(HANDLE processHandle);
    
    // Get full process information
    PVOID GetProcessInformation(HANDLE processHandle, PROCESSINFOCLASS infoClass, SIZE_T* returnLength = nullptr);
    
private:
    // Helper function to create a snapshot
    HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD processId);
    
    // Helper function to convert ProcessAccess to DWORD
    DWORD ProcessAccessToDWORD(ProcessAccess access);
    
    // Helper function to convert ThreadAccess to DWORD
    DWORD ThreadAccessToDWORD(ThreadAccess access);
    
    // Helper function to get process information
    bool GetProcessInfoByID(DWORD processId, ProcessInfo& info);
    
    // Helper function to fill module information
    bool GetModuleInfo(MODULEENTRY32W& me32, ModuleInfo& info);
    
    // Cache of process information
    std::unordered_map<std::wstring, ProcessInfo> processCache_;
    std::unordered_map<DWORD, ProcessInfo> processIdCache_;
    
    // Cache invalidation timer
    DWORD lastCacheUpdate_;
    const DWORD cacheValidityPeriod_ = 1000; // 1 second cache validity
};

} // namespace CS2Injector 