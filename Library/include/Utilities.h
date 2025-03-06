#pragma once

#include "Definitions.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace CS2Injector {
namespace Utilities {

// String conversion utilities
std::wstring StringToWideString(const std::string& str);
std::string WideStringToString(const std::wstring& wstr);
std::wstring UTF8ToWideString(const std::string& str);
std::string WideStringToUTF8(const std::wstring& wstr);

// Path utilities
std::wstring GetModulePath(HMODULE module = nullptr);
std::wstring GetModuleDirectory(HMODULE module = nullptr);
std::wstring GetCurrentDirectory();
std::wstring GetSystemDirectory();
std::wstring GetTempDirectory();
std::wstring CombinePath(const std::wstring& path1, const std::wstring& path2);
std::wstring GetPathDirectory(const std::wstring& path);
std::wstring GetPathFilename(const std::wstring& path);
std::wstring GetPathExtension(const std::wstring& path);
std::wstring ChangePathExtension(const std::wstring& path, const std::wstring& extension);
bool FileExists(const std::wstring& path);
bool DirectoryExists(const std::wstring& path);
bool CreateDirectoryRecursive(const std::wstring& path);
std::vector<std::wstring> GetFilesInDirectory(const std::wstring& directory, const std::wstring& pattern = L"*.*");

// Error handling utilities
std::wstring GetLastErrorAsString();
void LogError(const std::wstring& message, LogCallback logCallback = nullptr);
void DebugPrint(const std::wstring& message);
std::wstring FormatErrorMessage(const std::wstring& message, DWORD errorCode);

// Random utilities
BYTE GetRandomByte();
WORD GetRandomWord();
DWORD GetRandomDword();
PVOID GetRandomAddress(PVOID minAddress = nullptr, PVOID maxAddress = nullptr);
std::vector<BYTE> GenerateRandomBytes(SIZE_T count);
std::wstring GenerateRandomString(SIZE_T length);
std::wstring GenerateRandomFilename(const std::wstring& directory, const std::wstring& extension = L".dat");
DWORD GetRandomSleepTime(DWORD minTime = 10, DWORD maxTime = 100);

// Memory utilities
std::vector<BYTE> ReadFileToMemory(const std::wstring& filePath);
bool WriteMemoryToFile(const std::wstring& filePath, const void* data, SIZE_T size);
std::vector<BYTE> CompressData(const std::vector<BYTE>& data);
std::vector<BYTE> DecompressData(const std::vector<BYTE>& compressedData);
std::vector<BYTE> EncryptData(const std::vector<BYTE>& data, const std::vector<BYTE>& key);
std::vector<BYTE> DecryptData(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& key);
std::vector<BYTE> XorData(const std::vector<BYTE>& data, const std::vector<BYTE>& key);
std::vector<BYTE> RolData(const std::vector<BYTE>& data, int count);
std::vector<BYTE> RorData(const std::vector<BYTE>& data, int count);

// Shellcode utilities
std::vector<BYTE> CreateLoadLibraryShellcode(const std::wstring& dllPath);
std::vector<BYTE> CreateRemoteFunctionCallShellcode(PVOID functionAddress, PVOID parameter);
std::vector<BYTE> CreateReflectiveLoaderShellcode(const std::vector<BYTE>& dllData);
std::vector<BYTE> ObfuscateShellcode(const std::vector<BYTE>& shellcode);
std::vector<BYTE> CreateShellcodeTrampoline(PVOID targetAddress, const std::vector<BYTE>& shellcode);

// Timing utilities
void Sleep(DWORD milliseconds);
void SleepWithJitter(DWORD milliseconds, DWORD jitterPercent = 20);
ULONGLONG GetTickCount64();
bool WaitWithTimeout(std::function<bool()> predicate, DWORD timeout, DWORD checkInterval = 100);

// Process utilities
bool IsProcessElevated();
bool IsRunningAsAdmin();
DWORD GetCurrentProcessId();
std::wstring GetProcessCommandLine(DWORD processId);
bool IsProcess64Bit(DWORD processId);
bool Is64BitOperatingSystem();
bool InjectDLL(DWORD processId, const std::wstring& dllPath);
bool CreateProcessAndInject(const std::wstring& applicationPath, const std::wstring& dllPath, 
                           const std::wstring& commandLine = L"");

// Logging utilities
class Logger {
public:
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };
    
    Logger(const std::wstring& logFilePath = L"");
    ~Logger();
    
    void SetLogFile(const std::wstring& logFilePath);
    void SetLogLevel(LogLevel level);
    void SetLogCallback(LogCallback callback);
    
    void Debug(const std::wstring& message);
    void Info(const std::wstring& message);
    void Warning(const std::wstring& message);
    void Error(const std::wstring& message);
    void Critical(const std::wstring& message);
    
    void Log(LogLevel level, const std::wstring& message);
    
private:
    std::wstring FormatLogMessage(LogLevel level, const std::wstring& message);
    std::wstring LogLevelToString(LogLevel level);
    
    std::wstring logFilePath_;
    LogLevel logLevel_;
    LogCallback logCallback_;
    std::mutex logMutex_;
};

} // namespace Utilities
} // namespace CS2Injector 