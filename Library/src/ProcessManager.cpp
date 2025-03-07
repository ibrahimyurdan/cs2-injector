#include "../include/ProcessManager.h"
#include "../include/Utilities.h"

#include <Psapi.h>
#include <winternl.h>
#include <wtsapi32.h>

#pragma comment(lib, "wtsapi32.lib")

namespace CS2Injector {

// Constructor
ProcessManager::ProcessManager() 
    : lastCacheUpdate_(0) {
}

// Destructor
ProcessManager::~ProcessManager() {
    // No resources to clean up
}

// Get list of all processes
std::vector<ProcessInfo> ProcessManager::GetProcessList() {
    std::vector<ProcessInfo> processList;
    
    // Create snapshot of processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processList;
    }
    
    // Initialize process entry structure
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    // Iterate through processes
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            ProcessInfo info;
            if (GetProcessInfoByID(pe32.th32ProcessID, info)) {
                processList.push_back(info);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    // Clean up
    ::CloseHandle(hSnapshot);
    
    // Update cache timestamp
    lastCacheUpdate_ = GetTickCount();
    
    return processList;
}

// Get a process by name
ProcessInfo ProcessManager::GetProcessByName(const std::wstring& processName) {
    // Check cache first
    if (GetTickCount() - lastCacheUpdate_ < cacheValidityPeriod_ && 
        processCache_.find(processName) != processCache_.end()) {
        ProcessInfo cachedInfo = processCache_[processName];
        
        // Verify the process is still running
        if (IsProcessRunning(cachedInfo.id)) {
            return cachedInfo;
        }
    }
    
    // Cache miss or invalid cache, search for the process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return ProcessInfo();
    }
    
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                ::CloseHandle(hSnapshot);
                
                ProcessInfo info;
                if (GetProcessInfoByID(pe32.th32ProcessID, info)) {
                    // Update cache
                    processCache_[processName] = info;
                    processIdCache_[info.id] = info;
                    lastCacheUpdate_ = GetTickCount();
                    
                    return info;
                }
                
                return ProcessInfo();
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    ::CloseHandle(hSnapshot);
    return ProcessInfo();
}

// Get a process by ID
ProcessInfo ProcessManager::GetProcessById(DWORD processId) {
    // Check cache first
    if (GetTickCount() - lastCacheUpdate_ < cacheValidityPeriod_ && 
        processIdCache_.find(processId) != processIdCache_.end()) {
        return processIdCache_[processId];
    }
    
    // Cache miss or invalid cache, get process info
    ProcessInfo info;
    if (GetProcessInfoByID(processId, info)) {
        // Update cache
        processIdCache_[processId] = info;
        processCache_[info.name] = info;
        lastCacheUpdate_ = GetTickCount();
        
        return info;
    }
    
    return ProcessInfo();
}

// Check if a process is running
bool ProcessManager::IsProcessRunning(const std::wstring& processName) {
    return GetProcessByName(processName).id != 0;
}

bool ProcessManager::IsProcessRunning(DWORD processId) {
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    DWORD exitCode = 0;
    bool result = GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
    ::CloseHandle(hProcess);
    
    return result;
}

// Open a process with specified access rights
HANDLE ProcessManager::OpenProcess(const std::wstring& processName, ProcessAccess access) {
    ProcessInfo info = GetProcessByName(processName);
    if (info.id == 0) {
        return NULL;
    }
    
    return OpenProcess(info.id, access);
}

HANDLE ProcessManager::OpenProcess(DWORD processId, ProcessAccess access) {
    return ::OpenProcess(ProcessAccessToDWORD(access), FALSE, processId);
}

// Close a process handle
void ProcessManager::CloseProcess(HANDLE& handle) {
    if (handle && handle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(handle);
        handle = NULL;
    }
}

// Get the process path from a handle
std::wstring ProcessManager::GetProcessPath(HANDLE processHandle) {
    wchar_t path[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    
    if (!QueryFullProcessImageNameW(processHandle, 0, path, &size)) {
        return L"";
    }
    
    return path;
}

// Check if a process is 64-bit
bool ProcessManager::Is64BitProcess(HANDLE processHandle) {
    BOOL isWow64 = FALSE;
    
    // On 32-bit systems, there are no 64-bit processes
    if (sizeof(void*) == 4) {
        // If we're 32-bit and not running under WOW64, all processes are 32-bit
        if (!IsWow64Process(GetCurrentProcess(), &isWow64) || !isWow64) {
            return false;
        }
    }
    
    // On 64-bit Windows, processes that are not running under WOW64 are 64-bit
    if (!IsWow64Process(processHandle, &isWow64)) {
        return false;
    }
    
    return !isWow64;
}

// Get modules loaded in a process
std::vector<ModuleInfo> ProcessManager::GetProcessModules(HANDLE processHandle) {
    std::vector<ModuleInfo> modules;
    
    // Try EnumProcessModules first (more reliable but requires more access rights)
    HMODULE hModules[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(processHandle, hModules, sizeof(hModules), &cbNeeded)) {
        DWORD numModules = cbNeeded / sizeof(HMODULE);
        
        for (DWORD i = 0; i < numModules; i++) {
            ModuleInfo info;
            info.handle = hModules[i];
            info.baseAddress = hModules[i];
            
            MODULEINFO modInfo;
            if (GetModuleInformation(processHandle, hModules[i], &modInfo, sizeof(MODULEINFO))) {
                info.imageSize = modInfo.SizeOfImage;
            }
            
            wchar_t modName[MAX_PATH];
            if (GetModuleFileNameExW(processHandle, hModules[i], modName, MAX_PATH)) {
                info.path = modName;
                info.name = Utilities::GetPathFilename(modName);
            }
            
            modules.push_back(info);
        }
        
        return modules;
    }
    
    // Fall back to CreateToolhelp32Snapshot if EnumProcessModules fails
    DWORD processId = GetProcessId(processHandle);
    if (processId == 0) {
        return modules;
    }
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }
    
    MODULEENTRY32W me32 = { 0 };
    me32.dwSize = sizeof(MODULEENTRY32W);
    
    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            ModuleInfo info;
            if (GetModuleInfo(me32, info)) {
                modules.push_back(info);
            }
        } while (Module32NextW(hSnapshot, &me32));
    }
    
    ::CloseHandle(hSnapshot);
    return modules;
}

// Get a module by name
ModuleInfo ProcessManager::GetModuleByName(HANDLE processHandle, const std::wstring& moduleName) {
    std::vector<ModuleInfo> modules = GetProcessModules(processHandle);
    
    for (const auto& module : modules) {
        if (_wcsicmp(module.name.c_str(), moduleName.c_str()) == 0) {
            return module;
        }
    }
    
    return ModuleInfo();
}

// Check if a module is loaded
bool ProcessManager::IsModuleLoaded(HANDLE processHandle, const std::wstring& moduleName) {
    return GetModuleByName(processHandle, moduleName).handle != NULL;
}

// Get the base address of a module
PVOID ProcessManager::GetModuleBaseAddress(HANDLE processHandle, const std::wstring& moduleName) {
    return GetModuleByName(processHandle, moduleName).baseAddress;
}

// Get all threads in a process
std::vector<DWORD> ProcessManager::GetProcessThreads(DWORD processId) {
    std::vector<DWORD> threads;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return threads;
    }
    
    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                threads.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    ::CloseHandle(hSnapshot);
    return threads;
}

// Open a thread with specified access rights
HANDLE ProcessManager::OpenThread(DWORD threadId, ThreadAccess access) {
    return ::OpenThread(ThreadAccessToDWORD(access), FALSE, threadId);
}

// Close a thread handle
void ProcessManager::CloseThread(HANDLE& handle) {
    if (handle && handle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(handle);
        handle = NULL;
    }
}

// Suspend a process (all threads)
bool ProcessManager::SuspendProcess(DWORD processId) {
    std::vector<DWORD> threads = GetProcessThreads(processId);
    bool success = true;
    
    for (DWORD threadId : threads) {
        HANDLE hThread = OpenThread(threadId, ThreadAccess::SUSPEND_RESUME);
        if (hThread) {
            success &= SuspendThread(hThread) != (DWORD)-1;
            CloseThread(hThread);
        } else {
            success = false;
        }
    }
    
    return success;
}

// Resume a process (all threads)
bool ProcessManager::ResumeProcess(DWORD processId) {
    std::vector<DWORD> threads = GetProcessThreads(processId);
    bool success = true;
    
    for (DWORD threadId : threads) {
        HANDLE hThread = OpenThread(threadId, ThreadAccess::SUSPEND_RESUME);
        if (hThread) {
            success &= ResumeThread(hThread) != (DWORD)-1;
            CloseThread(hThread);
        } else {
            success = false;
        }
    }
    
    return success;
}

// Terminate a process
bool ProcessManager::TerminateProcess(DWORD processId, UINT exitCode) {
    HANDLE hProcess = OpenProcess(processId, ProcessAccess::TERMINATE);
    if (!hProcess) {
        return false;
    }
    
    bool result = ::TerminateProcess(hProcess, exitCode) != 0;
    CloseProcess(hProcess);
    
    return result;
}

// Wait for a process to exit
bool ProcessManager::WaitForProcessExit(DWORD processId, DWORD timeout) {
    HANDLE hProcess = OpenProcess(processId, ProcessAccess::SYNCHRONIZE);
    if (!hProcess) {
        return false;
    }
    
    DWORD result = WaitForSingleObject(hProcess, timeout);
    CloseProcess(hProcess);
    
    return result == WAIT_OBJECT_0;
}

// Create a new process
HANDLE ProcessManager::CreateProcess(const std::wstring& applicationPath, const std::wstring& commandLine, 
                                   bool suspended, DWORD* processId) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    
    // Prepare command line (application path + command line)
    std::wstring fullCommandLine = L"\"" + applicationPath + L"\" " + commandLine;
    std::vector<wchar_t> cmdLine(fullCommandLine.begin(), fullCommandLine.end());
    cmdLine.push_back(L'\0'); // Ensure null termination
    
    // Create the process
    if (!::CreateProcessW(
        applicationPath.c_str(),     // Application path
        cmdLine.data(),              // Command line
        NULL,                       // Process security attributes
        NULL,                       // Thread security attributes
        FALSE,                      // Inherit handles
        suspended ? CREATE_SUSPENDED : 0, // Creation flags
        NULL,                       // Environment
        NULL,                       // Current directory
        &si,                        // Startup info
        &pi                         // Process information
    )) {
        return NULL;
    }
    
    // Store process ID if requested
    if (processId) {
        *processId = pi.dwProcessId;
    }
    
    // Close the thread handle, we only care about the process
    ::CloseHandle(pi.hThread);
    
    return pi.hProcess;
}

// Inject a DLL into a process
bool ProcessManager::InjectDLL(HANDLE processHandle, const std::wstring& dllPath) {
    // Allocate memory for the DLL path
    SIZE_T dllPathSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID dllPathAddr = VirtualAllocEx(
        processHandle,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!dllPathAddr) {
        return false;
    }
    
    // Write the DLL path to the process memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(
        processHandle,
        dllPathAddr,
        dllPath.c_str(),
        dllPathSize,
        &bytesWritten
    ) || bytesWritten != dllPathSize) {
        VirtualFreeEx(processHandle, dllPathAddr, 0, MEM_RELEASE);
        return false;
    }
    
    // Get the address of LoadLibraryW
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        VirtualFreeEx(processHandle, dllPathAddr, 0, MEM_RELEASE);
        return false;
    }
    
    // Create a remote thread to call LoadLibraryW
    HANDLE hThread = ::CreateRemoteThread(
        processHandle,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        dllPathAddr,
        0,
        NULL
    );
    
    if (!hThread) {
        VirtualFreeEx(processHandle, dllPathAddr, 0, MEM_RELEASE);
        return false;
    }
    
    // Wait for the thread to complete
    WaitForSingleObject(hThread, INFINITE);
    
    // Get the thread exit code (which is the module handle of the loaded DLL)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    
    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(processHandle, dllPathAddr, 0, MEM_RELEASE);
    
    return exitCode != 0;
}

// Eject a DLL from a process
bool ProcessManager::EjectDLL(HANDLE processHandle, const std::wstring& dllName) {
    // Find the module handle
    ModuleInfo module = GetModuleByName(processHandle, dllName);
    if (!module.handle) {
        return false;
    }
    
    // Get the address of FreeLibrary
    FARPROC freeLibraryAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
    if (!freeLibraryAddr) {
        return false;
    }
    
    // Create a remote thread to call FreeLibrary
    HANDLE hThread = ::CreateRemoteThread(
        processHandle,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)freeLibraryAddr,
        module.handle,
        0,
        NULL
    );
    
    if (!hThread) {
        return false;
    }
    
    // Wait for the thread to complete
    WaitForSingleObject(hThread, INFINITE);
    
    // Get the thread exit code
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    
    // Clean up
    CloseHandle(hThread);
    
    return exitCode != 0;
}

// Enable debug privileges for the current process
bool ProcessManager::EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) != 0;
    CloseHandle(hToken);
    
    return result && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// Get the process integrity level
DWORD ProcessManager::GetProcessIntegrityLevel(HANDLE processHandle) {
    HANDLE hToken;
    DWORD integrityLevel = 0;
    
    if (!OpenProcessToken(processHandle, TOKEN_QUERY, &hToken)) {
        return 0;
    }
    
    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return 0;
    }
    
    PTOKEN_MANDATORY_LABEL pTokenInfo = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, tokenInfoLength);
    if (!pTokenInfo) {
        CloseHandle(hToken);
        return 0;
    }
    
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTokenInfo, tokenInfoLength, &tokenInfoLength)) {
        integrityLevel = *GetSidSubAuthority(
            pTokenInfo->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTokenInfo->Label.Sid) - 1)
        );
    }
    
    LocalFree(pTokenInfo);
    CloseHandle(hToken);
    
    return integrityLevel;
}

// Get the process DEP policy
bool ProcessManager::GetProcessDEPPolicy(HANDLE processHandle, BOOL* permanentDEP, BOOL* ATLThunkEmulation) {
    return GetProcessDEPPolicy(processHandle, permanentDEP, ATLThunkEmulation) != 0;
}

// Set the process DEP policy
bool ProcessManager::SetProcessDEPPolicy(HANDLE processHandle, DWORD flags) {
    // This requires NT API, which is not directly accessible
    // We would need to use NtSetInformationProcess
    // For now, we'll return false to indicate not implemented
    return false;
}

// Check if the process is being debugged
bool ProcessManager::IsBeingDebugged(HANDLE processHandle) {
    BOOL isDebugged = FALSE;
    
    // Try using CheckRemoteDebuggerPresent
    if (CheckRemoteDebuggerPresent(processHandle, &isDebugged)) {
        return isDebugged;
    }
    
    // Fall back to using NtQueryInformationProcess
    ULONG debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(
        processHandle,
        ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        NULL
    );
    
    return NT_SUCCESS(status) && debugPort != 0;
}

// Hide the process from the process list
bool ProcessManager::HideProcess(HANDLE processHandle) {
    // This requires a more complex approach, typically involving hooking or kernel mode
    // For now, we'll return false to indicate not implemented
    return false;
}

// Get full process information
PVOID ProcessManager::GetProcessInformation(HANDLE processHandle, PROCESSINFOCLASS infoClass, SIZE_T* returnLength) {
    // Determine the required buffer size
    ULONG infoLength = 0;
    NTSTATUS status = NtQueryInformationProcess(
        processHandle,
        infoClass,
        NULL,
        0,
        &infoLength
    );
    
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return nullptr;
    }
    
    // Allocate a buffer
    PVOID buffer = LocalAlloc(LPTR, infoLength);
    if (!buffer) {
        return nullptr;
    }
    
    // Get the information
    status = NtQueryInformationProcess(
        processHandle,
        infoClass,
        buffer,
        infoLength,
        &infoLength
    );
    
    if (!NT_SUCCESS(status)) {
        LocalFree(buffer);
        return nullptr;
    }
    
    if (returnLength) {
        *returnLength = infoLength;
    }
    
    return buffer;
}

// Helper function to create a snapshot
HANDLE ProcessManager::CreateToolhelp32Snapshot(DWORD flags, DWORD processId) {
    return ::CreateToolhelp32Snapshot(flags, processId);
}

// Helper function to convert ProcessAccess to DWORD
DWORD ProcessManager::ProcessAccessToDWORD(ProcessAccess access) {
    return static_cast<DWORD>(access);
}

// Helper function to convert ThreadAccess to DWORD
DWORD ProcessManager::ThreadAccessToDWORD(ThreadAccess access) {
    return static_cast<DWORD>(access);
}

// Helper function to get process information
bool ProcessManager::GetProcessInfoByID(DWORD processId, ProcessInfo& info) {
    info = ProcessInfo();
    info.id = processId;
    
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    // Get process name
    DWORD size = MAX_PATH;
    wchar_t processName[MAX_PATH] = { 0 };
    QueryFullProcessImageNameW(hProcess, 0, processName, &size);
    
    info.path = processName;
    info.name = Utilities::GetPathFilename(processName);
    info.handle = hProcess; // Caller is responsible for closing this handle
    info.is64Bit = Is64BitProcess(hProcess);
    
    return true;
}

// Helper function to fill module information
bool ProcessManager::GetModuleInfo(MODULEENTRY32W& me32, ModuleInfo& info) {
    info.handle = me32.hModule;
    info.name = me32.szModule;
    info.path = me32.szExePath;
    info.baseAddress = me32.modBaseAddr;
    info.imageSize = me32.modBaseSize;
    
    return true;
}

} // namespace CS2Injector 