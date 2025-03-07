#include "../include/ThreadHijacker.h"
#include "../include/Utilities.h"

#include <TlHelp32.h>
#include <psapi.h>

namespace CS2Injector {

// Constructor with process handle and memory manager
ThreadHijacker::ThreadHijacker(HANDLE processHandle, MemoryManager* memoryManager)
    : processHandle_(processHandle), memoryManager_(memoryManager) {
}

// Destructor
ThreadHijacker::~ThreadHijacker() {
    // Close any open thread handles
    for (auto& thread : cachedThreads_) {
        if (thread.handle && thread.handle != INVALID_HANDLE_VALUE) {
            CloseThreadHandle(thread.handle);
        }
    }
    
    // Free any allocated shellcode memory
    for (auto& addr : shellcodeAddresses_) {
        if (memoryManager_ && addr.second) {
            memoryManager_->FreeMemory(addr.second);
        }
    }
}

// Get all threads in the target process
std::vector<ThreadInfo> ThreadHijacker::GetProcessThreads() {
    // Clear the cached threads
    for (auto& thread : cachedThreads_) {
        CloseThreadHandle(thread.handle);
    }
    cachedThreads_.clear();
    
    // Get the process ID
    DWORD processId = GetProcessId(processHandle_);
    if (processId == 0) {
        return cachedThreads_; // Return empty vector
    }
    
    // Take a snapshot of all threads in the system
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return cachedThreads_; // Return empty vector
    }
    
    // Initialize thread entry structure
    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);
    
    // Get the first thread
    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return cachedThreads_; // Return empty vector
    }
    
    // Iterate over all threads
    do {
        // Check if this thread belongs to our target process
        if (te32.th32OwnerProcessID == processId) {
            ThreadInfo thread;
            thread.id = te32.th32ThreadID;
            thread.handle = OpenThread(thread.id, THREAD_ALL_ACCESS);
            thread.priority = te32.tpBasePri;
            thread.isSuspended = false; // Will be determined later
            thread.isMain = false; // Will be determined later
            
            // Try to get the thread context
            if (thread.handle) {
                thread.context.ContextFlags = CONTEXT_FULL;
                thread.isSuspended = (::SuspendThread(thread.handle) != (DWORD)-1);
                
                if (thread.isSuspended) {
                    GetThreadContext(thread.handle, thread.context);
                    ResumeThread(thread.handle);
                }
                
                // Try to get the thread start address
                ULONG_PTR startAddress = 0;
                NTSTATUS status = NtQueryInformationThread(
                    thread.handle,
                    (THREADINFOCLASS)9, // ThreadQuerySetWin32StartAddress
                    &startAddress,
                    sizeof(startAddress),
                    NULL
                );
                
                if (NT_SUCCESS(status)) {
                    thread.startAddress = (DWORD)startAddress;
                } else {
                    thread.startAddress = 0;
                }
            }
            
            // Add to our list
            cachedThreads_.push_back(thread);
        }
    } while (Thread32Next(hThreadSnap, &te32));
    
    // Clean up
    CloseHandle(hThreadSnap);
    
    // Try to determine the main thread
    if (!cachedThreads_.empty()) {
        ThreadInfo mainThread = FindMainThread();
        if (mainThread.id != 0) {
            for (auto& thread : cachedThreads_) {
                if (thread.id == mainThread.id) {
                    thread.isMain = true;
                    break;
                }
            }
        }
    }
    
    return cachedThreads_;
}

// Find a suitable thread for hijacking
ThreadInfo ThreadHijacker::FindSuitableThread() {
    // Make sure we have an up-to-date list of threads
    if (cachedThreads_.empty()) {
        GetProcessThreads();
    }
    
    // Try to find a non-main thread first
    for (auto& thread : cachedThreads_) {
        if (!thread.isMain && IsThreadSuitableForHijacking(thread)) {
            return thread;
        }
    }
    
    // If no suitable non-main thread, check if the main thread is suitable
    for (auto& thread : cachedThreads_) {
        if (thread.isMain && IsThreadSuitableForHijacking(thread)) {
            return thread;
        }
    }
    
    // If still no suitable thread, return the first thread that's not suspended
    for (auto& thread : cachedThreads_) {
        if (!thread.isSuspended) {
            return thread;
        }
    }
    
    // If all else fails, return an empty thread info
    return ThreadInfo();
}

// Hijack a thread to execute code
bool ThreadHijacker::HijackThread(DWORD threadId, LPVOID shellcode, SIZE_T shellcodeSize, bool resumeAfter) {
    HANDLE threadHandle = OpenThread(threadId, THREAD_ALL_ACCESS);
    if (!threadHandle) {
        return false;
    }
    
    bool result = HijackThreadInternal(threadHandle, shellcode, shellcodeSize, resumeAfter);
    
    CloseThreadHandle(threadHandle);
    return result;
}

// Hijack a thread by handle
bool ThreadHijacker::HijackThread(HANDLE threadHandle, LPVOID shellcode, SIZE_T shellcodeSize, bool resumeAfter) {
    return HijackThreadInternal(threadHandle, shellcode, shellcodeSize, resumeAfter);
}

// High-level method to inject DLL via thread hijacking
bool ThreadHijacker::InjectDLL(const std::wstring& dllPath, bool waitForCompletion) {
    // Generate LoadLibrary shellcode
    std::vector<BYTE> shellcode = GenerateShellcode(ShellcodeType::X64_LOADLIBRARY, dllPath);
    if (shellcode.empty()) {
        return false;
    }
    
    // Find a suitable thread
    ThreadInfo thread = FindSuitableThread();
    if (thread.id == 0 || !thread.handle) {
        return false;
    }
    
    // Allocate memory for the shellcode
    LPVOID shellcodeAddress = memoryManager_->AllocateMemory(shellcode.size(), PAGE_EXECUTE_READWRITE);
    if (!shellcodeAddress) {
        return false;
    }
    
    // Write the shellcode to the process memory
    if (!memoryManager_->WriteMemory(shellcodeAddress, shellcode.data(), shellcode.size())) {
        memoryManager_->FreeMemory(shellcodeAddress);
        return false;
    }
    
    // Store the shellcode address for cleanup
    shellcodeAddresses_[thread.id] = shellcodeAddress;
    
    // Hijack the thread to execute the shellcode
    bool result = HijackThread(thread.handle, shellcodeAddress, shellcode.size(), true);
    
    // Wait for completion if requested
    if (result && waitForCompletion) {
        // Wait for the thread to finish executing our shellcode
        // This is a simplified approach - in real scenarios you would need
        // a more sophisticated method to determine when the shellcode is done
        Utilities::Sleep(1000);
    }
    
    // Clean up
    memoryManager_->FreeMemory(shellcodeAddress);
    shellcodeAddresses_.erase(thread.id);
    
    return result;
}

// High-level method to inject and execute custom shellcode
bool ThreadHijacker::InjectShellcode(const std::vector<BYTE>& shellcode, bool waitForCompletion) {
    if (shellcode.empty()) {
        return false;
    }
    
    // Find a suitable thread
    ThreadInfo thread = FindSuitableThread();
    if (thread.id == 0 || !thread.handle) {
        return false;
    }
    
    // Allocate memory for the shellcode
    LPVOID shellcodeAddress = memoryManager_->AllocateMemory(shellcode.size(), PAGE_EXECUTE_READWRITE);
    if (!shellcodeAddress) {
        return false;
    }
    
    // Write the shellcode to the process memory
    if (!memoryManager_->WriteMemory(shellcodeAddress, shellcode.data(), shellcode.size())) {
        memoryManager_->FreeMemory(shellcodeAddress);
        return false;
    }
    
    // Store the shellcode address for cleanup
    shellcodeAddresses_[thread.id] = shellcodeAddress;
    
    // Hijack the thread to execute the shellcode
    bool result = HijackThread(thread.handle, shellcodeAddress, shellcode.size(), true);
    
    // Wait for completion if requested
    if (result && waitForCompletion) {
        // Wait for the thread to finish executing our shellcode
        // This is a simplified approach - in real scenarios you would need
        // a more sophisticated method to determine when the shellcode is done
        Utilities::Sleep(1000);
    }
    
    // Clean up
    memoryManager_->FreeMemory(shellcodeAddress);
    shellcodeAddresses_.erase(thread.id);
    
    return result;
}

// Generate shellcode for a specific task
std::vector<BYTE> ThreadHijacker::GenerateShellcode(ShellcodeType type, const std::wstring& dllPath) {
    switch (type) {
    case ShellcodeType::X64_LOADLIBRARY:
        return GenerateLoadLibraryShellcodeX64(dllPath);
    case ShellcodeType::X64_REFLECTIVE:
        return GenerateReflectiveShellcodeX64(dllPath);
    case ShellcodeType::X64_CUSTOM:
        // Custom shellcode generation would be implemented here
        return std::vector<BYTE>();
    default:
        return std::vector<BYTE>();
    }
}

// Suspend a thread
bool ThreadHijacker::SuspendThread(DWORD threadId) {
    HANDLE threadHandle = OpenThread(threadId, THREAD_SUSPEND_RESUME);
    if (!threadHandle) {
        return false;
    }
    
    DWORD result = ::SuspendThread(threadHandle);
    CloseThreadHandle(threadHandle);
    
    return result != (DWORD)-1;
}

// Resume a thread
bool ThreadHijacker::ResumeThread(DWORD threadId) {
    HANDLE threadHandle = OpenThread(threadId, THREAD_SUSPEND_RESUME);
    if (!threadHandle) {
        return false;
    }
    
    DWORD result = ::ResumeThread(threadHandle);
    CloseThreadHandle(threadHandle);
    
    return result != (DWORD)-1;
}

// Get the thread context
bool ThreadHijacker::GetThreadContext(DWORD threadId, CONTEXT& context) {
    HANDLE threadHandle = OpenThread(threadId, THREAD_GET_CONTEXT);
    if (!threadHandle) {
        return false;
    }
    
    context.ContextFlags = CONTEXT_FULL;
    bool result = ::GetThreadContext(threadHandle, &context) != 0;
    
    CloseThreadHandle(threadHandle);
    return result;
}

// Set the thread context
bool ThreadHijacker::SetThreadContext(DWORD threadId, const CONTEXT& context) {
    HANDLE threadHandle = OpenThread(threadId, THREAD_SET_CONTEXT);
    if (!threadHandle) {
        return false;
    }
    
    bool result = ::SetThreadContext(threadHandle, &context) != 0;
    
    CloseThreadHandle(threadHandle);
    return result;
}

// Wait for a thread to exit
bool ThreadHijacker::WaitForThreadExit(DWORD threadId, DWORD timeout) {
    HANDLE threadHandle = OpenThread(threadId, SYNCHRONIZE);
    if (!threadHandle) {
        return false;
    }
    
    DWORD result = WaitForSingleObject(threadHandle, timeout);
    CloseThreadHandle(threadHandle);
    
    return result == WAIT_OBJECT_0;
}

// Check if a thread is still active
bool ThreadHijacker::IsThreadActive(DWORD threadId) {
    HANDLE threadHandle = OpenThread(threadId, THREAD_QUERY_INFORMATION);
    if (!threadHandle) {
        return false;
    }
    
    DWORD exitCode;
    bool result = GetExitCodeThread(threadHandle, &exitCode) && exitCode == STILL_ACTIVE;
    
    CloseThreadHandle(threadHandle);
    return result;
}

// Find the main thread of the process
ThreadInfo ThreadHijacker::FindMainThread() {
    if (cachedThreads_.empty()) {
        GetProcessThreads();
    }
    
    if (cachedThreads_.empty()) {
        return ThreadInfo(); // Return empty thread info
    }
    
    // The main thread is usually the one with the lowest thread ID
    DWORD lowestId = MAXDWORD;
    ThreadInfo mainThread;
    
    for (auto& thread : cachedThreads_) {
        if (thread.id < lowestId) {
            lowestId = thread.id;
            mainThread = thread;
        }
    }
    
    return mainThread;
}

// Find a GUI thread (useful for UI applications)
ThreadInfo ThreadHijacker::FindGUIThread() {
    if (cachedThreads_.empty()) {
        GetProcessThreads();
    }
    
    // Look for a thread with a message queue
    for (auto& thread : cachedThreads_) {
        if (thread.handle) {
            GUITHREADINFO gti = { sizeof(GUITHREADINFO) };
            if (GetGUIThreadInfo(thread.id, &gti)) {
                return thread;
            }
        }
    }
    
    // If no GUI thread found, return an empty thread info
    return ThreadInfo();
}

// Get the current instruction pointer of a thread
DWORD_PTR ThreadHijacker::GetThreadInstructionPointer(DWORD threadId) {
    CONTEXT context;
    if (!GetThreadContext(threadId, context)) {
        return 0;
    }
    
#ifdef _WIN64
    return context.Rip;
#else
    return context.Eip;
#endif
}

// Get the current stack pointer of a thread
DWORD_PTR ThreadHijacker::GetThreadStackPointer(DWORD threadId) {
    CONTEXT context;
    if (!GetThreadContext(threadId, context)) {
        return 0;
    }
    
#ifdef _WIN64
    return context.Rsp;
#else
    return context.Esp;
#endif
}

// Internal function to perform the actual hijack
bool ThreadHijacker::HijackThreadInternal(HANDLE threadHandle, LPVOID shellcode, SIZE_T shellcodeSize, bool resumeAfter) {
    if (!threadHandle || shellcodeSize == 0 || !shellcode) {
        return false;
    }
    
    // Suspend the thread
    DWORD suspendCount = ::SuspendThread(threadHandle);
    if (suspendCount == (DWORD)-1) {
        return false;
    }
    
    // Get the thread ID for our records
    DWORD threadId = GetThreadId(threadHandle);
    
    // Save the original context
    CONTEXT originalContext;
    originalContext.ContextFlags = CONTEXT_FULL;
    if (!SaveThreadContext(threadHandle, originalContext)) {
        ::ResumeThread(threadHandle);
        return false;
    }
    
    // Store the original context for later restoration
    originalContexts_[threadId] = originalContext;
    
    // Create a new context for our shellcode
    CONTEXT shellcodeContext = CreateShellcodeContext(originalContext, shellcode);
    
    // Set the new context
    if (!RestoreThreadContext(threadHandle, shellcodeContext)) {
        // Try to restore the original context
        RestoreThreadContext(threadHandle, originalContext);
        ::ResumeThread(threadHandle);
        return false;
    }
    
    // Resume the thread to execute our shellcode
    if (resumeAfter) {
        ::ResumeThread(threadHandle);
    }
    
    return true;
}

// Save the original thread context
bool ThreadHijacker::SaveThreadContext(HANDLE threadHandle, CONTEXT& context) {
    context.ContextFlags = CONTEXT_FULL;
    return ::GetThreadContext(threadHandle, &context) != 0;
}

// Restore the original thread context
bool ThreadHijacker::RestoreThreadContext(HANDLE threadHandle, const CONTEXT& context) {
    return ::SetThreadContext(threadHandle, &context) != 0;
}

// Create a thread context for shellcode execution
CONTEXT ThreadHijacker::CreateShellcodeContext(const CONTEXT& originalContext, LPVOID shellcodeAddress) {
    CONTEXT shellcodeContext = originalContext;
    
#ifdef _WIN64
    // 64-bit architecture
    shellcodeContext.Rip = (DWORD64)shellcodeAddress;
#else
    // 32-bit architecture
    shellcodeContext.Eip = (DWORD)shellcodeAddress;
#endif
    
    return shellcodeContext;
}

// Find a safe location to inject shellcode
LPVOID ThreadHijacker::FindSafeShellcodeLocation(SIZE_T shellcodeSize) {
    // In a real-world scenario, you would need to be more careful about
    // choosing a safe location. This is a simplified implementation.
    
    // Allocate a new region of memory for the shellcode
    return memoryManager_->AllocateMemory(shellcodeSize, PAGE_EXECUTE_READWRITE);
}

// Generate LoadLibrary shellcode for x64
std::vector<BYTE> ThreadHijacker::GenerateLoadLibraryShellcodeX64(const std::wstring& dllPath) {
    // This is a simplified implementation. In a real-world scenario, you would
    // generate actual shellcode that calls LoadLibraryW with the DLL path.
    
    // For now, we'll delegate this to the Utilities method
    return Utilities::CreateLoadLibraryShellcode(dllPath);
}

// Generate reflective loading shellcode
std::vector<BYTE> ThreadHijacker::GenerateReflectiveShellcodeX64(const std::wstring& dllPath) {
    // This is a simplified implementation. In a real-world scenario, you would
    // generate actual shellcode that performs reflective DLL loading.
    
    // For now, we'll load the DLL into memory and then use the Utilities method
    std::vector<BYTE> dllData = Utilities::ReadFileToMemory(dllPath);
    if (dllData.empty()) {
        return std::vector<BYTE>();
    }
    
    return Utilities::CreateReflectiveLoaderShellcode(dllData);
}

// Helper to open a thread with required access
HANDLE ThreadHijacker::OpenThread(DWORD threadId, DWORD desiredAccess) {
    return ::OpenThread(desiredAccess, FALSE, threadId);
}

// Helper to safely close a thread handle
void ThreadHijacker::CloseThreadHandle(HANDLE& threadHandle) {
    if (threadHandle && threadHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(threadHandle);
        threadHandle = NULL;
    }
}

// Check if thread is suitable for hijacking
bool ThreadHijacker::IsThreadSuitableForHijacking(const ThreadInfo& thread) {
    // Check if the thread is active
    if (!thread.handle || !IsThreadActive(thread.id)) {
        return false;
    }
    
    // Avoid threads that are already suspended
    if (thread.isSuspended) {
        return false;
    }
    
    // Get current stack and instruction pointers
    DWORD_PTR ip = GetThreadInstructionPointer(thread.id);
    DWORD_PTR sp = GetThreadStackPointer(thread.id);
    
    // Make sure the thread has a valid instruction pointer and stack pointer
    if (ip == 0 || sp == 0) {
        return false;
    }
    
    // Avoid threads that are executing in sensitive areas
    // This would require more sophisticated analysis in a real implementation
    
    return true;
}

} // namespace CS2Injector 