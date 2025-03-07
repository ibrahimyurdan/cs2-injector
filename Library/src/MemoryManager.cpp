#include "../include/MemoryManager.h"
#include "../include/Utilities.h"

#include <TlHelp32.h>
#include <Psapi.h>

namespace CS2Injector {

// Constructor with process handle
MemoryManager::MemoryManager(HANDLE processHandle)
    : processHandle_(processHandle) {
    // Initialize random number generators
    std::random_device rd;
    rng_ = std::mt19937(rd());
    byteDist_ = std::uniform_int_distribution<BYTE>(0, 255);
    addressDist_ = std::uniform_int_distribution<DWORD>(0x00100000, 0x7FFF0000);
}

// Destructor
MemoryManager::~MemoryManager() {
    // No resources to clean up since we don't own the process handle
}

// Allocate memory in target process
PVOID MemoryManager::Allocate(SIZE_T size, MemoryProtection protection, 
                             MemoryAllocationType allocationType, PVOID preferredAddress) {
    return VirtualAllocEx(
        processHandle_,
        preferredAddress,
        size,
        static_cast<DWORD>(allocationType),
        static_cast<DWORD>(protection)
    );
}

// Allocate memory with randomization for anti-detection
PVOID MemoryManager::AllocateWithRandomization(SIZE_T size, MemoryProtection protection) {
    // Find a random memory region
    PVOID address = FindRandomMemoryRegion(size);
    
    if (!address) {
        // Fall back to normal allocation if random allocation fails
        return Allocate(size, protection);
    }
    
    // Allocate at the random address
    return Allocate(
        size,
        protection,
        MemoryAllocationType::COMMIT_RESERVE,
        address
    );
}

// Free allocated memory
bool MemoryManager::Free(PVOID address, SIZE_T size, DWORD freeType) {
    return VirtualFreeEx(processHandle_, address, size, freeType) != 0;
}

// Change memory protection
bool MemoryManager::Protect(PVOID address, SIZE_T size, MemoryProtection newProtection, MemoryProtection* oldProtection) {
    DWORD oldProtect = 0;
    bool result = VirtualProtectEx(
        processHandle_,
        address,
        size,
        static_cast<DWORD>(newProtection),
        &oldProtect
    ) != 0;
    
    if (oldProtection) {
        *oldProtection = static_cast<MemoryProtection>(oldProtect);
    }
    
    return result;
}

// Write memory to target process
bool MemoryManager::Write(PVOID targetAddress, LPCVOID data, SIZE_T size) {
    return WriteMemoryInternal(targetAddress, data, size, false);
}

// Read memory from target process
bool MemoryManager::Read(PVOID targetAddress, LPVOID buffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(processHandle_, targetAddress, buffer, size, &bytesRead) && bytesRead == size;
}

// Write memory with obfuscation
bool MemoryManager::WriteObfuscated(PVOID targetAddress, LPCVOID data, SIZE_T size) {
    return WriteMemoryInternal(targetAddress, data, size, true);
}

// Find memory region with specific pattern
PVOID MemoryManager::FindPattern(const std::vector<BYTE>& pattern, const std::vector<bool>& mask, 
                               PVOID startAddress, SIZE_T searchSize) {
    if (pattern.empty() || pattern.size() != mask.size()) {
        return nullptr;
    }
    
    // Read memory from target process
    std::vector<BYTE> buffer(searchSize);
    if (!Read(startAddress, buffer.data(), searchSize)) {
        return nullptr;
    }
    
    // Search for pattern
    for (SIZE_T i = 0; i <= searchSize - pattern.size(); i++) {
        bool found = true;
        
        for (SIZE_T j = 0; j < pattern.size(); j++) {
            if (mask[j] && buffer[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        
        if (found) {
            return reinterpret_cast<BYTE*>(startAddress) + i;
        }
    }
    
    return nullptr;
}

// Find pattern using string signature (like "48 8B ? ? E8 ? ? 89 ?? 00")
PVOID MemoryManager::FindPatternSignature(const std::string& signature, PVOID startAddress, SIZE_T searchSize) {
    std::vector<BYTE> pattern;
    std::vector<bool> mask;
    
    if (!ParsePatternString(signature, pattern, mask)) {
        return nullptr;
    }
    
    return FindPattern(pattern, mask, startAddress, searchSize);
}

// Get memory information
MemoryRegionInfo MemoryManager::QueryMemory(PVOID address) {
    MemoryRegionInfo info = {};
    MEMORY_BASIC_INFORMATION mbi = {};
    
    if (VirtualQueryEx(processHandle_, address, &mbi, sizeof(mbi))) {
        info.baseAddress = mbi.BaseAddress;
        info.regionSize = mbi.RegionSize;
        info.protection = static_cast<MemoryProtection>(mbi.Protect);
        info.state = mbi.State;
        info.type = mbi.Type;
    }
    
    return info;
}

// Get all memory regions
std::vector<MemoryRegionInfo> MemoryManager::GetMemoryMap() {
    std::vector<MemoryRegionInfo> memoryMap;
    PVOID address = nullptr;
    MEMORY_BASIC_INFORMATION mbi;
    
    while (VirtualQueryEx(processHandle_, address, &mbi, sizeof(mbi))) {
        MemoryRegionInfo info;
        info.baseAddress = mbi.BaseAddress;
        info.regionSize = mbi.RegionSize;
        info.protection = static_cast<MemoryProtection>(mbi.Protect);
        info.state = mbi.State;
        info.type = mbi.Type;
        
        memoryMap.push_back(info);
        
        // Move to the next memory region
        address = reinterpret_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        
        // Break if we've reached the end of the user-mode address space
        if (reinterpret_cast<uintptr_t>(address) >= 0x7FFFFFFF) {
            break;
        }
    }
    
    return memoryMap;
}

// Find a suitable memory region for allocation
PVOID MemoryManager::FindFreeMemoryRegion(SIZE_T size, PVOID preferredAddress, SIZE_T alignment) {
    PVOID currentAddress = preferredAddress ? preferredAddress : reinterpret_cast<PVOID>(0x00100000);
    
    while (true) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQueryEx(processHandle_, currentAddress, &mbi, sizeof(mbi))) {
            break;
        }
        
        // Check if this is a free region large enough
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            PVOID alignedAddress = currentAddress;
            
            // Apply alignment if specified
            if (alignment > 0) {
                uintptr_t addr = reinterpret_cast<uintptr_t>(currentAddress);
                alignedAddress = reinterpret_cast<PVOID>((addr + alignment - 1) & ~(alignment - 1));
                
                // Make sure the aligned address is still within the free region
                if (reinterpret_cast<BYTE*>(alignedAddress) + size <= 
                    reinterpret_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize) {
                    return alignedAddress;
                }
            } else {
                return currentAddress;
            }
        }
        
        // Move to the next region
        currentAddress = reinterpret_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        
        // Break if we've reached the end of the user-mode address space
        if (reinterpret_cast<uintptr_t>(currentAddress) >= 0x7FFFFFFF) {
            break;
        }
    }
    
    return nullptr;
}

// Copy memory between regions with proper protection handling
bool MemoryManager::CopyMemory(PVOID destination, PVOID source, SIZE_T size) {
    // This is a more complex operation since we need to:
    // 1. Get current protection of both source and destination
    // 2. Change protection to allow read/write
    // 3. Perform the copy
    // 4. Restore original protection
    
    MemoryRegionInfo sourceInfo = QueryMemory(source);
    MemoryRegionInfo destInfo = QueryMemory(destination);
    
    // Ensure we can read from source and write to destination
    bool sourceProtectionChanged = false;
    bool destProtectionChanged = false;
    MemoryProtection oldSourceProtect;
    MemoryProtection oldDestProtect;
    
    if ((static_cast<DWORD>(sourceInfo.protection) & PAGE_READWRITE) == 0) {
        sourceProtectionChanged = Protect(source, size, MemoryProtection::READ_WRITE, &oldSourceProtect);
        if (!sourceProtectionChanged) {
            return false;
        }
    }
    
    if ((static_cast<DWORD>(destInfo.protection) & PAGE_READWRITE) == 0) {
        destProtectionChanged = Protect(destination, size, MemoryProtection::READ_WRITE, &oldDestProtect);
        if (!destProtectionChanged) {
            // Restore source protection if it was changed
            if (sourceProtectionChanged) {
                Protect(source, size, oldSourceProtect);
            }
            return false;
        }
    }
    
    // Read from source
    std::vector<BYTE> buffer(size);
    bool readSuccess = Read(source, buffer.data(), size);
    
    if (!readSuccess) {
        // Restore protections
        if (sourceProtectionChanged) {
            Protect(source, size, oldSourceProtect);
        }
        if (destProtectionChanged) {
            Protect(destination, size, oldDestProtect);
        }
        return false;
    }
    
    // Write to destination
    bool writeSuccess = Write(destination, buffer.data(), size);
    
    // Restore protections
    if (sourceProtectionChanged) {
        Protect(source, size, oldSourceProtect);
    }
    if (destProtectionChanged) {
        Protect(destination, size, oldDestProtect);
    }
    
    return writeSuccess;
}

// Zero memory region
bool MemoryManager::ZeroMemory(PVOID address, SIZE_T size) {
    std::vector<BYTE> zeros(size, 0);
    return Write(address, zeros.data(), size);
}

// Fill memory with random data
bool MemoryManager::FillWithRandomData(PVOID address, SIZE_T size) {
    std::vector<BYTE> randomData(size);
    for (SIZE_T i = 0; i < size; i++) {
        randomData[i] = byteDist_(rng_);
    }
    
    return Write(address, randomData.data(), size);
}

// Clean PE headers to avoid detection
bool MemoryManager::CleanPEHeaders(PVOID baseAddress) {
    // We need to be careful not to corrupt essential information
    // Typically, we zero out the header but leave the DOS header intact
    // This is a common anti-detection technique
    
    // Read the first 4KB, which typically contains the PE headers
    std::vector<BYTE> headers(4096);
    if (!Read(baseAddress, headers.data(), headers.size())) {
        return false;
    }
    
    // Verify it's a valid PE file
    if (headers[0] != 'M' || headers[1] != 'Z') {
        return false;
    }
    
    // Get e_lfanew (offset to PE header)
    DWORD peOffset = *reinterpret_cast<DWORD*>(&headers[0x3C]);
    if (peOffset >= headers.size() - 4) {
        return false;
    }
    
    // Verify PE signature
    if (headers[peOffset] != 'P' || headers[peOffset + 1] != 'E' || 
        headers[peOffset + 2] != 0 || headers[peOffset + 3] != 0) {
        return false;
    }
    
    // Zero out everything except the DOS header (first 64 bytes)
    for (SIZE_T i = 64; i < headers.size(); i++) {
        headers[i] = 0;
    }
    
    // Write back the modified headers
    return Write(baseAddress, headers.data(), headers.size());
}

// Get process handle
HANDLE MemoryManager::GetProcessHandle() const {
    return processHandle_;
}

// Helper to convert string pattern to byte pattern and mask
bool MemoryManager::ParsePatternString(const std::string& patternStr, std::vector<BYTE>& pattern, std::vector<bool>& mask) {
    pattern.clear();
    mask.clear();
    
    std::string token;
    std::istringstream tokenStream(patternStr);
    
    while (std::getline(tokenStream, token, ' ')) {
        if (token == "??" || token == "?") {
            // Wildcard
            pattern.push_back(0);
            mask.push_back(false);
        } else {
            // Convert hex string to byte
            char* endPtr;
            BYTE value = static_cast<BYTE>(std::strtol(token.c_str(), &endPtr, 16));
            
            if (*endPtr != '\0') {
                // Invalid hex string
                pattern.clear();
                mask.clear();
                return false;
            }
            
            pattern.push_back(value);
            mask.push_back(true);
        }
    }
    
    return !pattern.empty();
}

// Find suitable memory region for randomized allocation
PVOID MemoryManager::FindRandomMemoryRegion(SIZE_T size) {
    // Get a list of all free memory regions
    std::vector<MemoryRegionInfo> memoryMap = GetMemoryMap();
    std::vector<MemoryRegionInfo> freeRegions;
    
    for (const auto& region : memoryMap) {
        if (region.state == MEM_FREE && region.regionSize >= size) {
            freeRegions.push_back(region);
        }
    }
    
    if (freeRegions.empty()) {
        return nullptr;
    }
    
    // Pick a random free region
    std::uniform_int_distribution<size_t> regionDist(0, freeRegions.size() - 1);
    const MemoryRegionInfo& selectedRegion = freeRegions[regionDist(rng_)];
    
    // Pick a random address within the region that can fit our allocation
    SIZE_T maxOffset = selectedRegion.regionSize - size;
    std::uniform_int_distribution<SIZE_T> offsetDist(0, maxOffset);
    SIZE_T offset = offsetDist(rng_);
    
    // Ensure the address is aligned to 64K (common allocation granularity)
    offset = (offset + 0xFFFF) & ~0xFFFF;
    
    // Make sure we're still within bounds after alignment
    if (offset > maxOffset) {
        offset = 0;
    }
    
    return reinterpret_cast<BYTE*>(selectedRegion.baseAddress) + offset;
}

// Internal implementation to write memory with different methods
bool MemoryManager::WriteMemoryInternal(PVOID targetAddress, LPCVOID data, SIZE_T size, bool obfuscate) {
    if (obfuscate) {
        // Obfuscate the data
        std::vector<BYTE> obfuscatedData = ObfuscateData(static_cast<const BYTE*>(data), size);
        
        // Write the obfuscated data
        SIZE_T bytesWritten = 0;
        bool result = WriteProcessMemory(processHandle_, targetAddress, obfuscatedData.data(), obfuscatedData.size(), &bytesWritten);
        
        if (!result || bytesWritten != obfuscatedData.size()) {
            return false;
        }
        
        // Deobfuscate the data in-place within the target process
        // In a real implementation, we would use a more sophisticated approach,
        // such as injecting a small thread to do the deobfuscation
        std::vector<BYTE> deobfuscatedData = DeobfuscateData(obfuscatedData.data(), obfuscatedData.size());
        
        bytesWritten = 0;
        return WriteProcessMemory(processHandle_, targetAddress, deobfuscatedData.data(), size, &bytesWritten) && bytesWritten == size;
    } else {
        // Write directly without obfuscation
        SIZE_T bytesWritten = 0;
        return WriteProcessMemory(processHandle_, targetAddress, data, size, &bytesWritten) && bytesWritten == size;
    }
}

// Apply polymorphic obfuscation to data
std::vector<BYTE> MemoryManager::ObfuscateData(const BYTE* data, SIZE_T size) {
    // Simple XOR obfuscation for demonstration
    // In a real implementation, you'd use a more sophisticated technique
    std::vector<BYTE> result(size);
    
    // Generate a random key
    BYTE key = byteDist_(rng_);
    
    // XOR each byte with the key
    for (SIZE_T i = 0; i < size; i++) {
        result[i] = data[i] ^ key;
    }
    
    // Prepend the key to the result
    result.insert(result.begin(), key);
    
    return result;
}

// Deobfuscate data
std::vector<BYTE> MemoryManager::DeobfuscateData(const BYTE* data, SIZE_T size) {
    if (size <= 1) {
        return std::vector<BYTE>();
    }
    
    // First byte is the key
    BYTE key = data[0];
    
    // Decrypt the rest of the data
    std::vector<BYTE> result(size - 1);
    for (SIZE_T i = 0; i < size - 1; i++) {
        result[i] = data[i + 1] ^ key;
    }
    
    return result;
}

// Generate random shellcode for memory writing
std::vector<BYTE> MemoryManager::GenerateWriteShellcode(PVOID targetAddress, const std::vector<BYTE>& data) {
    // This is a placeholder - in a real implementation, you would generate
    // actual assembly code to write the data
    
    return std::vector<BYTE>();
}

} // namespace CS2Injector 