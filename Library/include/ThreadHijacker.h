#pragma once

#include "Definitions.h"
#include "MemoryManager.h"

namespace CS2Injector {

// Thread information structure
struct ThreadInfo {
    DWORD id;
    HANDLE handle;
    CONTEXT context;
    DWORD startAddress;
    DWORD priority;
    bool isSuspended;
    bool isMain;
};

// Shellcode types for injection
enum class ShellcodeType {
    X64_LOADLIBRARY,        // 64-bit LoadLibrary shellcode
    X64_CUSTOM,             // 64-bit custom shellcode
    X64_REFLECTIVE          // 64-bit reflective loading shellcode
};

class API_EXPORT ThreadHijacker {
public:
    // Constructor with process handle and memory manager
    ThreadHijacker(HANDLE processHandle, MemoryManager* memoryManager);
    
    // Destructor
    ~ThreadHijacker();
    
    // Get all threads in the target process
    std::vector<ThreadInfo> GetProcessThreads();
    
    // Find a suitable thread for hijacking
    ThreadInfo FindSuitableThread();
    
    // Hijack a thread to execute code
    bool HijackThread(DWORD threadId, LPVOID shellcode, SIZE_T shellcodeSize, bool resumeAfter = true);
    
    // Hijack a thread by handle
    bool HijackThread(HANDLE threadHandle, LPVOID shellcode, SIZE_T shellcodeSize, bool resumeAfter = true);
    
    // High-level method to inject DLL via thread hijacking
    bool InjectDLL(const std::wstring& dllPath, bool waitForCompletion = true);
    
    // High-level method to inject and execute custom shellcode
    bool InjectShellcode(const std::vector<BYTE>& shellcode, bool waitForCompletion = true);
    
    // Generate shellcode for a specific task
    std::vector<BYTE> GenerateShellcode(ShellcodeType type, const std::wstring& dllPath = L"");
    
    // Suspend a thread
    bool SuspendThread(DWORD threadId);
    
    // Resume a thread
    bool ResumeThread(DWORD threadId);
    
    // Get the thread context
    bool GetThreadContext(DWORD threadId, CONTEXT& context);
    
    // Set the thread context
    bool SetThreadContext(DWORD threadId, const CONTEXT& context);
    
    // Wait for a thread to exit
    bool WaitForThreadExit(DWORD threadId, DWORD timeout);
    
    // Check if a thread is still active
    bool IsThreadActive(DWORD threadId);
    
    // Find the main thread of the process
    ThreadInfo FindMainThread();
    
    // Find a GUI thread (useful for UI applications)
    ThreadInfo FindGUIThread();
    
    // Get the current instruction pointer of a thread
    DWORD_PTR GetThreadInstructionPointer(DWORD threadId);
    
    // Get the current stack pointer of a thread
    DWORD_PTR GetThreadStackPointer(DWORD threadId);
    
private:
    // Internal function to perform the actual hijack
    bool HijackThreadInternal(HANDLE threadHandle, LPVOID shellcode, SIZE_T shellcodeSize, bool resumeAfter);
    
    // Save the original thread context
    bool SaveThreadContext(HANDLE threadHandle, CONTEXT& context);
    
    // Restore the original thread context
    bool RestoreThreadContext(HANDLE threadHandle, const CONTEXT& context);
    
    // Create a thread context for shellcode execution
    CONTEXT CreateShellcodeContext(const CONTEXT& originalContext, LPVOID shellcodeAddress);
    
    // Find a safe location to inject shellcode
    LPVOID FindSafeShellcodeLocation(SIZE_T shellcodeSize);
    
    // Generate LoadLibrary shellcode for x64
    std::vector<BYTE> GenerateLoadLibraryShellcodeX64(const std::wstring& dllPath);
    
    // Generate reflective loading shellcode
    std::vector<BYTE> GenerateReflectiveShellcodeX64(const std::wstring& dllPath);
    
    // Helper to open a thread with required access
    HANDLE OpenThread(DWORD threadId, DWORD desiredAccess);
    
    // Helper to safely close a thread handle
    void CloseThreadHandle(HANDLE& threadHandle);
    
    // Check if thread is suitable for hijacking
    bool IsThreadSuitableForHijacking(const ThreadInfo& thread);
    
    // Process handle
    HANDLE processHandle_;
    
    // Memory manager
    MemoryManager* memoryManager_;
    
    // Cache of process threads
    std::vector<ThreadInfo> cachedThreads_;
    
    // Map of original thread contexts for restoration
    std::unordered_map<DWORD, CONTEXT> originalContexts_;
    
    // Map of allocated shellcode addresses for cleanup
    std::unordered_map<DWORD, LPVOID> shellcodeAddresses_;
};

} // namespace CS2Injector 