#pragma once

#include "Definitions.h"
#include <random>

namespace CS2Injector {

// Memory protection options
enum class MemoryProtection {
    NO_ACCESS = PAGE_NOACCESS,
    READ_ONLY = PAGE_READONLY,
    READ_WRITE = PAGE_READWRITE,
    WRITE_COPY = PAGE_WRITECOPY,
    EXECUTE = PAGE_EXECUTE,
    EXECUTE_READ = PAGE_EXECUTE_READ,
    EXECUTE_READ_WRITE = PAGE_EXECUTE_READWRITE,
    EXECUTE_WRITE_COPY = PAGE_EXECUTE_WRITECOPY
};

// Memory allocation types
enum class MemoryAllocationType {
    COMMIT = MEM_COMMIT,
    RESERVE = MEM_RESERVE,
    COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE,
    RESET = MEM_RESET,
    TOP_DOWN = MEM_TOP_DOWN,
    PHYSICAL = MEM_PHYSICAL,
    LARGE_PAGES = MEM_LARGE_PAGES
};

// Memory information
struct MemoryRegionInfo {
    PVOID baseAddress;
    SIZE_T regionSize;
    MemoryProtection protection;
    DWORD state; // MEM_COMMIT, MEM_FREE, MEM_RESERVE
    DWORD type;  // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
};

class API_EXPORT MemoryManager {
public:
    // Constructor with process handle
    MemoryManager(HANDLE processHandle);
    
    // Destructor
    ~MemoryManager();
    
    // Allocate memory in target process
    PVOID Allocate(SIZE_T size, MemoryProtection protection = MemoryProtection::READ_WRITE, 
                  MemoryAllocationType allocationType = MemoryAllocationType::COMMIT_RESERVE, 
                  PVOID preferredAddress = nullptr);
    
    // Allocate memory with randomization for anti-detection
    PVOID AllocateWithRandomization(SIZE_T size, MemoryProtection protection = MemoryProtection::READ_WRITE);
    
    // Free allocated memory
    bool Free(PVOID address, SIZE_T size = 0, DWORD freeType = MEM_RELEASE);
    
    // Change memory protection
    bool Protect(PVOID address, SIZE_T size, MemoryProtection newProtection, MemoryProtection* oldProtection = nullptr);
    
    // Write memory to target process
    bool Write(PVOID targetAddress, LPCVOID data, SIZE_T size);
    
    // Read memory from target process
    bool Read(PVOID targetAddress, LPVOID buffer, SIZE_T size);
    
    // Write memory with obfuscation
    bool WriteObfuscated(PVOID targetAddress, LPCVOID data, SIZE_T size);
    
    // Find memory region with specific pattern
    PVOID FindPattern(const std::vector<BYTE>& pattern, const std::vector<bool>& mask, 
                     PVOID startAddress, SIZE_T searchSize);
    
    // Find pattern using string signature (like "48 8B ? ? E8 ? ? 89 ?? 00")
    PVOID FindPatternSignature(const std::string& signature, PVOID startAddress, SIZE_T searchSize);
    
    // Get memory information
    MemoryRegionInfo QueryMemory(PVOID address);
    
    // Get all memory regions
    std::vector<MemoryRegionInfo> GetMemoryMap();
    
    // Find a suitable memory region for allocation
    PVOID FindFreeMemoryRegion(SIZE_T size, PVOID preferredAddress = nullptr, SIZE_T alignment = 0);
    
    // Copy memory between regions with proper protection handling
    bool CopyMemory(PVOID destination, PVOID source, SIZE_T size);
    
    // Zero memory region
    bool ZeroMemory(PVOID address, SIZE_T size);
    
    // Fill memory with random data
    bool FillWithRandomData(PVOID address, SIZE_T size);
    
    // Clean PE headers to avoid detection
    bool CleanPEHeaders(PVOID baseAddress);
    
    // Get process handle
    HANDLE GetProcessHandle() const;
    
private:
    // Helper to convert string pattern to byte pattern and mask
    bool ParsePatternString(const std::string& patternStr, std::vector<BYTE>& pattern, std::vector<bool>& mask);
    
    // Find suitable memory region for randomized allocation
    PVOID FindRandomMemoryRegion(SIZE_T size);
    
    // Internal implementation to write memory with different methods
    bool WriteMemoryInternal(PVOID targetAddress, LPCVOID data, SIZE_T size, bool obfuscate);
    
    // Apply polymorphic obfuscation to data
    std::vector<BYTE> ObfuscateData(const BYTE* data, SIZE_T size);
    
    // Deobfuscate data
    std::vector<BYTE> DeobfuscateData(const BYTE* data, SIZE_T size);
    
    // Generate random shellcode for memory writing
    std::vector<BYTE> GenerateWriteShellcode(PVOID targetAddress, const std::vector<BYTE>& data);
    
    // Process handle
    HANDLE processHandle_;
    
    // Random number generator for obfuscation and randomization
    std::mt19937 rng_;
    std::uniform_int_distribution<BYTE> byteDist_;
    std::uniform_int_distribution<DWORD> addressDist_;
};

} // namespace CS2Injector 