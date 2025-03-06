#pragma once

#include "Definitions.h"
#include <unordered_map>

namespace CS2Injector {

// PE File characteristics
struct PEFileInfo {
    bool isValid;
    bool is64Bit;
    DWORD entryPointRVA;
    SIZE_T imageSize;
    DWORD imageBase;
    std::vector<BYTE> headerData;
    
    // PE Sections
    struct Section {
        std::string name;
        DWORD virtualAddress;
        DWORD virtualSize;
        DWORD rawDataOffset;
        DWORD rawDataSize;
        DWORD characteristics;
        std::vector<BYTE> data;
    };
    std::vector<Section> sections;
    
    // Import information
    struct ImportFunction {
        std::string name;
        DWORD rva;
        WORD hint;
        bool isOrdinal;
        WORD ordinal;
    };
    
    struct ImportModule {
        std::string name;
        DWORD rva;
        std::vector<ImportFunction> functions;
    };
    std::vector<ImportModule> imports;
    
    // Export information
    struct ExportFunction {
        std::string name;
        DWORD rva;
        WORD ordinal;
    };
    std::vector<ExportFunction> exports;
    std::string exportModuleName;
    
    // Relocation information
    struct RelocationBlock {
        DWORD pageRVA;
        std::vector<WORD> offsets;
    };
    std::vector<RelocationBlock> relocations;
    
    // TLS callbacks
    std::vector<DWORD> tlsCallbacks;
    DWORD tlsStartAddressRVA;
    DWORD tlsEndAddressRVA;
    DWORD tlsIndexAddressRVA;
    DWORD tlsCallbacksAddressRVA;
    DWORD tlsZeroFillSize;
    DWORD tlsCharacteristics;
};

class API_EXPORT PEParser {
public:
    // Constructor with path to PE file
    PEParser(const std::wstring& filePath);
    
    // Constructor with memory buffer
    PEParser(const std::vector<BYTE>& data);
    
    // Destructor
    ~PEParser();
    
    // Parse the PE file
    bool Parse();
    
    // Get information about the PE file
    const PEFileInfo& GetFileInfo() const;
    
    // Get the raw file data
    const std::vector<BYTE>& GetRawData() const;
    
    // Validate PE file
    bool ValidatePE() const;
    
    // Check if file is 64-bit
    bool Is64Bit() const;
    
    // Get the entry point
    DWORD GetEntryPoint() const;
    
    // Get the image size
    SIZE_T GetImageSize() const;
    
    // Get the image base
    DWORD GetImageBase() const;
    
    // Get a section by name
    const PEFileInfo::Section* GetSectionByName(const std::string& name) const;
    
    // Get a section that contains RVA
    const PEFileInfo::Section* GetSectionByRVA(DWORD rva) const;
    
    // Convert RVA to file offset
    DWORD RvaToOffset(DWORD rva) const;
    
    // Convert file offset to RVA
    DWORD OffsetToRva(DWORD offset) const;
    
    // Get import modules
    const std::vector<PEFileInfo::ImportModule>& GetImports() const;
    
    // Get export functions
    const std::vector<PEFileInfo::ExportFunction>& GetExports() const;
    
    // Get relocation blocks
    const std::vector<PEFileInfo::RelocationBlock>& GetRelocations() const;
    
    // Get TLS callbacks
    const std::vector<DWORD>& GetTLSCallbacks() const;
    
private:
    // Parse DOS header
    bool ParseDOSHeader();
    
    // Parse NT headers
    bool ParseNTHeaders();
    
    // Parse sections
    bool ParseSections();
    
    // Parse imports
    bool ParseImports();
    
    // Parse exports
    bool ParseExports();
    
    // Parse relocations
    bool ParseRelocations();
    
    // Parse TLS
    bool ParseTLS();
    
    // Private members
    std::wstring filePath_;
    std::vector<BYTE> data_;
    PEFileInfo fileInfo_;
    bool isParsed_;
    
    // Cached offset map for quick RVA to offset conversion
    std::unordered_map<DWORD, DWORD> rvaToOffsetCache_;
};

} // namespace CS2Injector 