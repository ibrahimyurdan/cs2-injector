#include "../include/PEParser.h"
#include "../include/Utilities.h"

#include <fstream>
#include <algorithm>

namespace CS2Injector {

// Static helper methods for PE validation and checks
bool IsValidPE(const BYTE* data, SIZE_T size) {
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    if (size < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    return true;
}

PIMAGE_NT_HEADERS GetNTHeaders(const BYTE* data) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data;
    return (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);
}

bool IsPE64Bit(const std::wstring& filePath) {
    std::vector<BYTE> fileData;
    if (!Utilities::ReadFileToMemory(filePath, fileData)) {
        return false;
    }
    
    if (!IsValidPE(fileData.data(), fileData.size())) {
        return false;
    }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileData.data() + dosHeader->e_lfanew);
    
    return ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}

// Constructor with path to PE file
PEParser::PEParser(const std::wstring& filePath) 
    : filePath_(filePath), isParsed_(false) {
    fileInfo_.isValid = false;
}

// Constructor with memory buffer
PEParser::PEParser(const std::vector<BYTE>& data) 
    : data_(data), isParsed_(false) {
    fileInfo_.isValid = false;
}

// Destructor
PEParser::~PEParser() {
    // Clean up any resources
}

// Parse the PE file
bool PEParser::Parse() {
    // If already parsed, return true
    if (isParsed_) {
        return fileInfo_.isValid;
    }
    
    // If data is empty, load it from file
    if (data_.empty() && !filePath_.empty()) {
        if (!Utilities::ReadFileToMemory(filePath_, data_)) {
            return false;
        }
    }
    
    // Check if data is valid
    if (data_.empty()) {
        return false;
    }
    
    // Initialize file info
    fileInfo_ = PEFileInfo();
    
    // Parse headers
    if (!ParseDOSHeader()) {
        return false;
    }
    
    if (!ParseNTHeaders()) {
        return false;
    }
    
    if (!ParseSections()) {
        return false;
    }
    
    // Parse tables
    ParseImports();
    ParseExports();
    ParseRelocations();
    ParseTLS();
    
    // Mark as parsed
    isParsed_ = true;
    fileInfo_.isValid = true;
    
    return true;
}

// Get information about the PE file
const PEFileInfo& PEParser::GetFileInfo() const {
    return fileInfo_;
}

// Get the raw file data
const std::vector<BYTE>& PEParser::GetRawData() const {
    return data_;
}

// Validate PE file
bool PEParser::ValidatePE() const {
    return fileInfo_.isValid;
}

// Check if file is 64-bit
bool PEParser::Is64Bit() const {
    return fileInfo_.is64Bit;
}

// Get the entry point
DWORD PEParser::GetEntryPoint() const {
    return fileInfo_.entryPointRVA;
}

// Get the image size
SIZE_T PEParser::GetImageSize() const {
    return fileInfo_.imageSize;
}

// Get the image base
DWORD PEParser::GetImageBase() const {
    return fileInfo_.imageBase;
}

// Get a section by name
const PEFileInfo::Section* PEParser::GetSectionByName(const std::string& name) const {
    for (const auto& section : fileInfo_.sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

// Get a section that contains RVA
const PEFileInfo::Section* PEParser::GetSectionByRVA(DWORD rva) const {
    for (const auto& section : fileInfo_.sections) {
        if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
            return &section;
        }
    }
    return nullptr;
}

// Convert RVA to file offset
DWORD PEParser::RvaToOffset(DWORD rva) const {
    // Check cache first
    auto it = rvaToOffsetCache_.find(rva);
    if (it != rvaToOffsetCache_.end()) {
        return it->second;
    }
    
    // Find the section containing this RVA
    const PEFileInfo::Section* section = GetSectionByRVA(rva);
    if (!section) {
        return 0;
    }
    
    // Calculate the offset
    DWORD offset = section->rawDataOffset + (rva - section->virtualAddress);
    
    // Cache the result
    const_cast<PEParser*>(this)->rvaToOffsetCache_[rva] = offset;
    
    return offset;
}

// Convert file offset to RVA
DWORD PEParser::OffsetToRva(DWORD offset) const {
    for (const auto& section : fileInfo_.sections) {
        if (offset >= section.rawDataOffset && offset < section.rawDataOffset + section.rawDataSize) {
            return section.virtualAddress + (offset - section.rawDataOffset);
        }
    }
    return 0;
}

// Get import modules
const std::vector<PEFileInfo::ImportModule>& PEParser::GetImports() const {
    return fileInfo_.imports;
}

// Get export functions
const std::vector<PEFileInfo::ExportFunction>& PEParser::GetExports() const {
    return fileInfo_.exports;
}

// Get relocation blocks
const std::vector<PEFileInfo::RelocationBlock>& PEParser::GetRelocations() const {
    return fileInfo_.relocations;
}

// Get TLS callbacks
const std::vector<DWORD>& PEParser::GetTLSCallbacks() const {
    return fileInfo_.tlsCallbacks;
}

// Parse DOS header
bool PEParser::ParseDOSHeader() {
    if (data_.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data_.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    return true;
}

// Parse NT headers
bool PEParser::ParseNTHeaders() {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data_.data();
    if (data_.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data_.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    // Check architecture
    fileInfo_.is64Bit = ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    
    // Extract basic info
    fileInfo_.entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    fileInfo_.imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    fileInfo_.imageBase = ntHeaders->OptionalHeader.ImageBase;
    
    // Store the headers for later use
    DWORD headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    fileInfo_.headerData.resize(headerSize);
    std::copy(data_.begin(), data_.begin() + headerSize, fileInfo_.headerData.begin());
    
    return true;
}

// Parse sections
bool PEParser::ParseSections() {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data_.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data_.data() + dosHeader->e_lfanew);
    
    // Get section headers
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    
    // Reserve space for sections
    fileInfo_.sections.reserve(numSections);
    
    // Parse each section
    for (WORD i = 0; i < numSections; i++) {
        PEFileInfo::Section section;
        
        // Copy name (convert from char to string)
        char sectionName[9] = { 0 }; // IMAGE_SIZEOF_SHORT_NAME + 1
        memcpy(sectionName, sectionHeader[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        section.name = sectionName;
        
        // Copy section info
        section.virtualAddress = sectionHeader[i].VirtualAddress;
        section.virtualSize = sectionHeader[i].Misc.VirtualSize;
        section.rawDataOffset = sectionHeader[i].PointerToRawData;
        section.rawDataSize = sectionHeader[i].SizeOfRawData;
        section.characteristics = sectionHeader[i].Characteristics;
        
        // Copy section data
        if (section.rawDataOffset > 0 && section.rawDataSize > 0 && section.rawDataOffset + section.rawDataSize <= data_.size()) {
            section.data.resize(section.rawDataSize);
            std::copy(data_.begin() + section.rawDataOffset, data_.begin() + section.rawDataOffset + section.rawDataSize, section.data.begin());
        }
        
        // Add to sections list
        fileInfo_.sections.push_back(section);
    }
    
    return true;
}

// Parse imports
bool PEParser::ParseImports() {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data_.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data_.data() + dosHeader->e_lfanew);
    
    // Get import directory
    DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    
    if (importDirRVA == 0 || importDirSize == 0) {
        // No imports
        return true;
    }
    
    // Convert RVA to file offset
    DWORD importDirOffset = RvaToOffset(importDirRVA);
    if (importDirOffset == 0) {
        return false;
    }
    
    // Parse each import descriptor
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(data_.data() + importDirOffset);
    
    for (int i = 0; importDesc[i].Name != 0; i++) {
        PEFileInfo::ImportModule importModule;
        
        // Get module name
        DWORD nameOffset = RvaToOffset(importDesc[i].Name);
        if (nameOffset == 0) {
            continue;
        }
        
        importModule.name = (char*)(data_.data() + nameOffset);
        importModule.rva = importDesc[i].FirstThunk;
        
        // Get the functions
        DWORD thunkRVA = importDesc[i].OriginalFirstThunk ? importDesc[i].OriginalFirstThunk : importDesc[i].FirstThunk;
        DWORD thunkOffset = RvaToOffset(thunkRVA);
        
        if (thunkOffset == 0) {
            continue;
        }
        
        // 32-bit or 64-bit
        if (fileInfo_.is64Bit) {
            // 64-bit
            IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(data_.data() + thunkOffset);
            
            for (int j = 0; thunk[j].u1.AddressOfData != 0; j++) {
                PEFileInfo::ImportFunction importFunc;
                
                if (thunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    // Import by ordinal
                    importFunc.isOrdinal = true;
                    importFunc.ordinal = IMAGE_ORDINAL64(thunk[j].u1.Ordinal);
                    importFunc.name = "#" + std::to_string(importFunc.ordinal);
                } else {
                    // Import by name
                    DWORD importOffset = RvaToOffset((DWORD)thunk[j].u1.AddressOfData);
                    if (importOffset == 0) {
                        continue;
                    }
                    
                    IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(data_.data() + importOffset);
                    importFunc.isOrdinal = false;
                    importFunc.name = (char*)importByName->Name;
                    importFunc.hint = importByName->Hint;
                }
                
                importFunc.rva = importDesc[i].FirstThunk + j * sizeof(IMAGE_THUNK_DATA64);
                importModule.functions.push_back(importFunc);
            }
        } else {
            // 32-bit
            IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(data_.data() + thunkOffset);
            
            for (int j = 0; thunk[j].u1.AddressOfData != 0; j++) {
                PEFileInfo::ImportFunction importFunc;
                
                if (thunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    // Import by ordinal
                    importFunc.isOrdinal = true;
                    importFunc.ordinal = IMAGE_ORDINAL32(thunk[j].u1.Ordinal);
                    importFunc.name = "#" + std::to_string(importFunc.ordinal);
                } else {
                    // Import by name
                    DWORD importOffset = RvaToOffset(thunk[j].u1.AddressOfData);
                    if (importOffset == 0) {
                        continue;
                    }
                    
                    IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(data_.data() + importOffset);
                    importFunc.isOrdinal = false;
                    importFunc.name = (char*)importByName->Name;
                    importFunc.hint = importByName->Hint;
                }
                
                importFunc.rva = importDesc[i].FirstThunk + j * sizeof(IMAGE_THUNK_DATA32);
                importModule.functions.push_back(importFunc);
            }
        }
        
        fileInfo_.imports.push_back(importModule);
    }
    
    return true;
}

// Parse exports
bool PEParser::ParseExports() {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data_.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data_.data() + dosHeader->e_lfanew);
    
    // Get export directory
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    
    if (exportDirRVA == 0 || exportDirSize == 0) {
        // No exports
        return true;
    }
    
    // Convert RVA to file offset
    DWORD exportDirOffset = RvaToOffset(exportDirRVA);
    if (exportDirOffset == 0) {
        return false;
    }
    
    // Parse export directory
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(data_.data() + exportDirOffset);
    
    // Get module name
    DWORD nameOffset = RvaToOffset(exportDir->Name);
    if (nameOffset > 0) {
        fileInfo_.exportModuleName = (char*)(data_.data() + nameOffset);
    }
    
    // Get function addresses
    DWORD addressTableOffset = RvaToOffset(exportDir->AddressOfFunctions);
    DWORD nameTableOffset = RvaToOffset(exportDir->AddressOfNames);
    DWORD ordinalTableOffset = RvaToOffset(exportDir->AddressOfNameOrdinals);
    
    if (addressTableOffset == 0) {
        return false;
    }
    
    // Get all exported functions
    DWORD* addressTable = (DWORD*)(data_.data() + addressTableOffset);
    
    // If there's a name table, use it
    if (nameTableOffset > 0 && ordinalTableOffset > 0) {
        DWORD* nameTable = (DWORD*)(data_.data() + nameTableOffset);
        WORD* ordinalTable = (WORD*)(data_.data() + ordinalTableOffset);
        
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            PEFileInfo::ExportFunction exportFunc;
            
            DWORD nameOffset = RvaToOffset(nameTable[i]);
            if (nameOffset == 0) {
                continue;
            }
            
            exportFunc.name = (char*)(data_.data() + nameOffset);
            exportFunc.ordinal = ordinalTable[i] + exportDir->Base;
            exportFunc.rva = addressTable[ordinalTable[i]];
            
            // Check if it's a forwarded export
            if (exportFunc.rva >= exportDirRVA && exportFunc.rva < exportDirRVA + exportDirSize) {
                // This is a forwarded export
                DWORD forwardOffset = RvaToOffset(exportFunc.rva);
                if (forwardOffset > 0) {
                    exportFunc.name += " -> " + std::string((char*)(data_.data() + forwardOffset));
                }
            }
            
            fileInfo_.exports.push_back(exportFunc);
        }
    } else {
        // No name table, just use ordinals
        for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++) {
            if (addressTable[i] == 0) {
                continue;
            }
            
            PEFileInfo::ExportFunction exportFunc;
            exportFunc.name = "#" + std::to_string(i + exportDir->Base);
            exportFunc.ordinal = i + exportDir->Base;
            exportFunc.rva = addressTable[i];
            
            // Check if it's a forwarded export
            if (exportFunc.rva >= exportDirRVA && exportFunc.rva < exportDirRVA + exportDirSize) {
                // This is a forwarded export
                DWORD forwardOffset = RvaToOffset(exportFunc.rva);
                if (forwardOffset > 0) {
                    exportFunc.name += " -> " + std::string((char*)(data_.data() + forwardOffset));
                }
            }
            
            fileInfo_.exports.push_back(exportFunc);
        }
    }
    
    return true;
}

// Parse relocations
bool PEParser::ParseRelocations() {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data_.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data_.data() + dosHeader->e_lfanew);
    
    // Get relocation directory
    DWORD relocDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    if (relocDirRVA == 0 || relocDirSize == 0) {
        // No relocations
        return true;
    }
    
    // Convert RVA to file offset
    DWORD relocDirOffset = RvaToOffset(relocDirRVA);
    if (relocDirOffset == 0) {
        return false;
    }
    
    // Parse relocation blocks
    DWORD offset = relocDirOffset;
    while (offset < relocDirOffset + relocDirSize) {
        IMAGE_BASE_RELOCATION* relocBlock = (IMAGE_BASE_RELOCATION*)(data_.data() + offset);
        if (relocBlock->SizeOfBlock == 0) {
            break;
        }
        
        PEFileInfo::RelocationBlock block;
        block.pageRVA = relocBlock->VirtualAddress;
        
        // Get the relocation entries
        DWORD numEntries = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((BYTE*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < numEntries; i++) {
            block.offsets.push_back(entries[i]);
        }
        
        fileInfo_.relocations.push_back(block);
        offset += relocBlock->SizeOfBlock;
    }
    
    return true;
}

// Parse TLS
bool PEParser::ParseTLS() {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data_.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data_.data() + dosHeader->e_lfanew);
    
    // Get TLS directory
    DWORD tlsDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DWORD tlsDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    
    if (tlsDirRVA == 0 || tlsDirSize == 0) {
        // No TLS
        return true;
    }
    
    // Convert RVA to file offset
    DWORD tlsDirOffset = RvaToOffset(tlsDirRVA);
    if (tlsDirOffset == 0) {
        return false;
    }
    
    // Parse TLS directory
    if (fileInfo_.is64Bit) {
        // 64-bit
        IMAGE_TLS_DIRECTORY64* tlsDir = (IMAGE_TLS_DIRECTORY64*)(data_.data() + tlsDirOffset);
        
        fileInfo_.tlsStartAddressRVA = (DWORD)(tlsDir->StartAddressOfRawData - ntHeaders->OptionalHeader.ImageBase);
        fileInfo_.tlsEndAddressRVA = (DWORD)(tlsDir->EndAddressOfRawData - ntHeaders->OptionalHeader.ImageBase);
        fileInfo_.tlsIndexAddressRVA = (DWORD)(tlsDir->AddressOfIndex - ntHeaders->OptionalHeader.ImageBase);
        fileInfo_.tlsCallbacksAddressRVA = (DWORD)(tlsDir->AddressOfCallBacks - ntHeaders->OptionalHeader.ImageBase);
        fileInfo_.tlsZeroFillSize = tlsDir->SizeOfZeroFill;
        fileInfo_.tlsCharacteristics = tlsDir->Characteristics;
        
        // Parse callbacks
        if (tlsDir->AddressOfCallBacks != 0) {
            DWORD callbacksOffset = RvaToOffset(fileInfo_.tlsCallbacksAddressRVA);
            if (callbacksOffset > 0) {
                ULONGLONG* callbacks = (ULONGLONG*)(data_.data() + callbacksOffset);
                for (int i = 0; callbacks[i] != 0; i++) {
                    fileInfo_.tlsCallbacks.push_back((DWORD)(callbacks[i] - ntHeaders->OptionalHeader.ImageBase));
                }
            }
        }
    } else {
        // 32-bit
        IMAGE_TLS_DIRECTORY32* tlsDir = (IMAGE_TLS_DIRECTORY32*)(data_.data() + tlsDirOffset);
        
        fileInfo_.tlsStartAddressRVA = tlsDir->StartAddressOfRawData - ntHeaders->OptionalHeader.ImageBase;
        fileInfo_.tlsEndAddressRVA = tlsDir->EndAddressOfRawData - ntHeaders->OptionalHeader.ImageBase;
        fileInfo_.tlsIndexAddressRVA = tlsDir->AddressOfIndex - ntHeaders->OptionalHeader.ImageBase;
        fileInfo_.tlsCallbacksAddressRVA = tlsDir->AddressOfCallBacks - ntHeaders->OptionalHeader.ImageBase;
        fileInfo_.tlsZeroFillSize = tlsDir->SizeOfZeroFill;
        fileInfo_.tlsCharacteristics = tlsDir->Characteristics;
        
        // Parse callbacks
        if (tlsDir->AddressOfCallBacks != 0) {
            DWORD callbacksOffset = RvaToOffset(fileInfo_.tlsCallbacksAddressRVA);
            if (callbacksOffset > 0) {
                DWORD* callbacks = (DWORD*)(data_.data() + callbacksOffset);
                for (int i = 0; callbacks[i] != 0; i++) {
                    fileInfo_.tlsCallbacks.push_back(callbacks[i] - ntHeaders->OptionalHeader.ImageBase);
                }
            }
        }
    }
    
    return true;
}

} // namespace CS2Injector 