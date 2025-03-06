#pragma once

#include "Definitions.h"
#include "MemoryManager.h"

namespace CS2Injector {

// Evasion techniques enumeration
enum class EvasionTechnique {
    MEMORY_CLOAKING,           // Hide memory regions from scanning
    TIMING_MANIPULATION,       // Manipulate timing checks
    HOOK_DETECTION_BYPASS,     // Bypass hook detection methods
    SIGNATURE_RANDOMIZATION,   // Randomize signatures
    CODE_INTEGRITY_BYPASS,     // Bypass code integrity checks
    PROCESS_LIST_SPOOFING,     // Spoof process listings
    THREAD_HIDING,             // Hide threads from enumeration
    MODULE_CONCEALMENT,        // Conceal loaded modules
    CALL_STACK_CLEANING,       // Clean call stacks
    DEBUGGER_DETECTION_BYPASS  // Bypass debugger detection
};

// VAC scan detection modes
enum class VACDetectionMode {
    PASSIVE,      // Only detect potential scans
    ACTIVE,       // Detect and take evasive action
    AGGRESSIVE    // Actively counteract scanning
};

class API_EXPORT VAC {
public:
    // Constructor with process handle and memory manager
    VAC(HANDLE processHandle, MemoryManager* memoryManager);
    
    // Destructor
    ~VAC();
    
    // Enable specific evasion technique
    bool EnableEvasionTechnique(EvasionTechnique technique);
    
    // Disable specific evasion technique
    bool DisableEvasionTechnique(EvasionTechnique technique);
    
    // Check if a technique is enabled
    bool IsTechniqueEnabled(EvasionTechnique technique) const;
    
    // Enable all evasion techniques
    void EnableAllTechniques();
    
    // Apply all enabled evasion techniques
    bool ApplyEvasionTechniques();
    
    // Set VAC scan detection mode
    void SetDetectionMode(VACDetectionMode mode);
    
    // Get current detection mode
    VACDetectionMode GetDetectionMode() const;
    
    // Check if VAC is currently scanning the process
    bool IsVACScanning() const;
    
    // Protect a memory region from VAC scans
    bool ProtectMemoryRegion(PVOID address, SIZE_T size);
    
    // Unprotect a previously protected memory region
    bool UnprotectMemoryRegion(PVOID address);
    
    // Hide a module from VAC module list
    bool HideModule(HMODULE module);
    
    // Unhide a previously hidden module
    bool UnhideModule(HMODULE module);
    
    // Cloak memory by creating fake regions
    bool CloakMemory(PVOID address, SIZE_T size);
    
    // Bypass signature scanning for a memory region
    bool BypassSignatureScanning(PVOID address, SIZE_T size);
    
    // Apply timing manipulation to confuse scans
    bool ApplyTimingManipulation();
    
    // Clean PE headers to prevent detection
    bool CleanPEHeaders(PVOID baseAddress);
    
    // Obfuscate imports to prevent detection
    bool ObfuscateImports(PVOID baseAddress);
    
    // Spoof call stack to hide suspicious calls
    bool SpoofCallStack();
    
    // Detect and handle VAC module loading
    bool HandleVACModuleLoading();
    
    // Monitor for potential VAC scans
    void StartVACScanMonitoring();
    
    // Stop VAC scan monitoring
    void StopVACScanMonitoring();
    
    // Bypass integrity checking for a code region
    bool BypassIntegrityCheck(PVOID address, SIZE_T size);
    
    // Apply defensive measures against VAC
    bool ApplyDefensiveMeasures();
    
private:
    // Internal methods for evasion techniques
    bool ApplyMemoryCloaking();
    bool ApplyTimingManipulationInternal();
    bool ApplyHookDetectionBypass();
    bool ApplySignatureRandomization();
    bool ApplyCodeIntegrityBypass();
    bool ApplyProcessListSpoofing();
    bool ApplyThreadHiding();
    bool ApplyModuleConcealment();
    bool ApplyCallStackCleaning();
    bool ApplyDebuggerDetectionBypass();
    
    // Detect VAC scanning techniques
    bool DetectMemoryScanning() const;
    bool DetectModuleEnumeration() const;
    bool DetectThreadEnumeration() const;
    bool DetectCodeIntegrityChecks() const;
    bool DetectTimingChecks() const;
    
    // Generate misdirection for VAC scans
    void GenerateMisdirection();
    
    // Create decoy data to mislead scanning
    void CreateDecoys();
    
    // Patch known VAC scanning functions
    bool PatchVACFunctions();
    
    // Find and analyze VAC modules
    void AnalyzeVACModules();
    
    // Process handle
    HANDLE processHandle_;
    
    // Memory manager
    MemoryManager* memoryManager_;
    
    // Enabled techniques
    std::unordered_map<EvasionTechnique, bool> enabledTechniques_;
    
    // Protected memory regions
    std::vector<std::pair<PVOID, SIZE_T>> protectedRegions_;
    
    // Hidden modules
    std::vector<HMODULE> hiddenModules_;
    
    // Current detection mode
    VACDetectionMode detectionMode_;
    
    // Flag indicating if monitoring is active
    bool isMonitoring_;
    
    // Thread handle for monitoring
    HANDLE monitoringThread_;
};

} // namespace CS2Injector 