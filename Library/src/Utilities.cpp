#include "../include/Utilities.h"

#include <Windows.h>
#include <fstream>
#include <chrono>
#include <thread>
#include <codecvt>
#include <locale>
#include <shlwapi.h>
#include <shlobj.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace CS2Injector {
namespace Utilities {

// Random number generator
std::random_device rd;
std::mt19937 gen(rd());

// String conversion utilities
std::wstring StringToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

std::string WideStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

std::wstring UTF8ToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

std::string WideStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

// Path utilities
std::wstring GetModulePath(HMODULE module) {
    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(module, path, MAX_PATH);
    return path;
}

std::wstring GetModuleDirectory(HMODULE module) {
    std::wstring path = GetModulePath(module);
    size_t pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(0, pos) : path;
}

std::wstring GetCurrentDirectory() {
    wchar_t path[MAX_PATH] = { 0 };
    ::GetCurrentDirectoryW(MAX_PATH, path);
    return path;
}

std::wstring GetSystemDirectory() {
    wchar_t path[MAX_PATH] = { 0 };
    ::GetSystemDirectoryW(path, MAX_PATH);
    return path;
}

std::wstring GetTempDirectory() {
    wchar_t path[MAX_PATH] = { 0 };
    ::GetTempPathW(MAX_PATH, path);
    return path;
}

std::wstring CombinePath(const std::wstring& path1, const std::wstring& path2) {
    wchar_t result[MAX_PATH] = { 0 };
    PathCombineW(result, path1.c_str(), path2.c_str());
    return result;
}

std::wstring GetPathDirectory(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(0, pos) : L"";
}

std::wstring GetPathFilename(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}

std::wstring GetPathExtension(const std::wstring& path) {
    size_t pos = path.find_last_of(L'.');
    return (pos != std::wstring::npos) ? path.substr(pos) : L"";
}

std::wstring ChangePathExtension(const std::wstring& path, const std::wstring& extension) {
    size_t pos = path.find_last_of(L'.');
    return (pos != std::wstring::npos) ? path.substr(0, pos) + extension : path + extension;
}

bool FileExists(const std::wstring& path) {
    DWORD attrib = GetFileAttributesW(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool DirectoryExists(const std::wstring& path) {
    DWORD attrib = GetFileAttributesW(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool CreateDirectoryRecursive(const std::wstring& path) {
    if (path.empty()) return false;
    
    if (DirectoryExists(path)) return true;
    
    std::wstring parentPath = GetPathDirectory(path);
    if (!parentPath.empty() && !DirectoryExists(parentPath)) {
        if (!CreateDirectoryRecursive(parentPath)) return false;
    }
    
    return CreateDirectoryW(path.c_str(), NULL) != 0;
}

std::vector<std::wstring> GetFilesInDirectory(const std::wstring& directory, const std::wstring& pattern) {
    std::vector<std::wstring> files;
    WIN32_FIND_DATAW findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    
    std::wstring searchPath = CombinePath(directory, pattern);
    hFind = FindFirstFileW(searchPath.c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                files.push_back(CombinePath(directory, findData.cFileName));
            }
        } while (FindNextFileW(hFind, &findData) != 0);
        FindClose(hFind);
    }
    
    return files;
}

// Error handling utilities
std::wstring GetLastErrorAsString() {
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0)
        return std::wstring();
    
    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);
    
    std::wstring message(messageBuffer, size);
    LocalFree(messageBuffer);
    
    return message;
}

void LogError(const std::wstring& message, LogCallback logCallback) {
    std::wstring errorMessage = message + L": " + GetLastErrorAsString();
    if (logCallback) {
        logCallback(errorMessage);
    } else {
        DebugPrint(errorMessage);
    }
}

void DebugPrint(const std::wstring& message) {
    OutputDebugStringW(message.c_str());
}

std::wstring FormatErrorMessage(const std::wstring& message, DWORD errorCode) {
    LPWSTR errorMessage = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&errorMessage, 0, NULL);
    
    std::wstring result = message + L": " + std::wstring(errorMessage);
    LocalFree(errorMessage);
    
    return result;
}

// Random utilities
BYTE GetRandomByte() {
    std::uniform_int_distribution<> dist(0, 255);
    return static_cast<BYTE>(dist(gen));
}

WORD GetRandomWord() {
    std::uniform_int_distribution<> dist(0, 65535);
    return static_cast<WORD>(dist(gen));
}

DWORD GetRandomDword() {
    std::uniform_int_distribution<DWORD> dist(0, MAXDWORD);
    return dist(gen);
}

PVOID GetRandomAddress(PVOID minAddress, PVOID maxAddress) {
    ULONG_PTR min = reinterpret_cast<ULONG_PTR>(minAddress ? minAddress : (PVOID)0x10000);
    ULONG_PTR max = reinterpret_cast<ULONG_PTR>(maxAddress ? maxAddress : (PVOID)0x7FFFFFFF);
    
    std::uniform_int_distribution<ULONG_PTR> dist(min, max);
    return reinterpret_cast<PVOID>(dist(gen));
}

std::vector<BYTE> GenerateRandomBytes(SIZE_T count) {
    std::vector<BYTE> result(count);
    for (SIZE_T i = 0; i < count; i++) {
        result[i] = GetRandomByte();
    }
    return result;
}

std::wstring GenerateRandomString(SIZE_T length) {
    static const wchar_t charset[] = 
        L"0123456789"
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        L"abcdefghijklmnopqrstuvwxyz";
    
    std::wstring result;
    result.reserve(length);
    
    std::uniform_int_distribution<> dist(0, sizeof(charset) / sizeof(charset[0]) - 2);
    
    for (SIZE_T i = 0; i < length; i++) {
        result += charset[dist(gen)];
    }
    
    return result;
}

std::wstring GenerateRandomFilename(const std::wstring& directory, const std::wstring& extension) {
    std::wstring filename;
    do {
        filename = CombinePath(directory, GenerateRandomString(12) + extension);
    } while (FileExists(filename));
    
    return filename;
}

DWORD GetRandomSleepTime(DWORD minTime, DWORD maxTime) {
    std::uniform_int_distribution<DWORD> dist(minTime, maxTime);
    return dist(gen);
}

// Memory utilities
std::vector<BYTE> ReadFileToMemory(const std::wstring& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return std::vector<BYTE>();
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<BYTE> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return std::vector<BYTE>();
    }
    
    return buffer;
}

bool WriteMemoryToFile(const std::wstring& filePath, const void* data, SIZE_T size) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data), size);
    return !file.fail();
}

std::vector<BYTE> CompressData(const std::vector<BYTE>& data) {
    // This is a simple placeholder for compression
    // In a real implementation, you would use a compression library like zlib
    return data;
}

std::vector<BYTE> DecompressData(const std::vector<BYTE>& compressedData) {
    // This is a simple placeholder for decompression
    // In a real implementation, you would use a compression library like zlib
    return compressedData;
}

std::vector<BYTE> EncryptData(const std::vector<BYTE>& data, const std::vector<BYTE>& key) {
    // This is a simple XOR encryption for demonstration
    return XorData(data, key);
}

std::vector<BYTE> DecryptData(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& key) {
    // XOR is its own inverse, so decryption is the same as encryption
    return XorData(encryptedData, key);
}

std::vector<BYTE> XorData(const std::vector<BYTE>& data, const std::vector<BYTE>& key) {
    if (key.empty() || data.empty()) {
        return data;
    }
    
    std::vector<BYTE> result = data;
    for (size_t i = 0; i < data.size(); i++) {
        result[i] ^= key[i % key.size()];
    }
    
    return result;
}

std::vector<BYTE> RolData(const std::vector<BYTE>& data, int count) {
    std::vector<BYTE> result = data;
    for (BYTE& b : result) {
        b = (b << count) | (b >> (8 - count));
    }
    return result;
}

std::vector<BYTE> RorData(const std::vector<BYTE>& data, int count) {
    std::vector<BYTE> result = data;
    for (BYTE& b : result) {
        b = (b >> count) | (b << (8 - count));
    }
    return result;
}

// Shellcode utilities
std::vector<BYTE> CreateLoadLibraryShellcode(const std::wstring& dllPath) {
    // This is a simplified example that doesn't actually generate real shellcode
    // In a real implementation, you would generate proper assembly code
    // for calling LoadLibraryW
    
    // Just return an empty vector for now
    return std::vector<BYTE>();
}

std::vector<BYTE> CreateRemoteFunctionCallShellcode(PVOID functionAddress, PVOID parameter) {
    // This is a simplified example that doesn't actually generate real shellcode
    // In a real implementation, you would generate proper assembly code
    // for calling a function with a parameter
    
    // Just return an empty vector for now
    return std::vector<BYTE>();
}

std::vector<BYTE> CreateReflectiveLoaderShellcode(const std::vector<BYTE>& dllData) {
    // This is a simplified example that doesn't actually generate real shellcode
    // In a real implementation, you would generate proper assembly code
    // for a reflective DLL loader
    
    // Just return an empty vector for now
    return std::vector<BYTE>();
}

std::vector<BYTE> ObfuscateShellcode(const std::vector<BYTE>& shellcode) {
    // This is a simplified example that doesn't actually obfuscate the shellcode
    // In a real implementation, you would apply various obfuscation techniques
    
    // Just return the original shellcode for now
    return shellcode;
}

std::vector<BYTE> CreateShellcodeTrampoline(PVOID targetAddress, const std::vector<BYTE>& shellcode) {
    // This is a simplified example that doesn't actually generate a trampoline
    // In a real implementation, you would generate proper assembly code
    // for a trampoline that calls the shellcode and returns to the original code
    
    // Just return an empty vector for now
    return std::vector<BYTE>();
}

// Timing utilities
void Sleep(DWORD milliseconds) {
    ::Sleep(milliseconds);
}

void SleepWithJitter(DWORD milliseconds, DWORD jitterPercent) {
    DWORD jitterRange = (milliseconds * jitterPercent) / 100;
    DWORD jitterValue = jitterRange > 0 ? GetRandomDword() % jitterRange : 0;
    DWORD sleepTime = milliseconds + jitterValue - (jitterRange / 2);
    
    ::Sleep(sleepTime);
}

ULONGLONG GetTickCount64() {
    return ::GetTickCount64();
}

bool WaitWithTimeout(std::function<bool()> predicate, DWORD timeout, DWORD checkInterval) {
    ULONGLONG startTime = GetTickCount64();
    ULONGLONG endTime = startTime + timeout;
    
    while (GetTickCount64() < endTime) {
        if (predicate()) {
            return true;
        }
        
        ::Sleep(checkInterval);
    }
    
    return false;
}

// Process utilities
bool IsProcessElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            fRet = elevation.TokenIsElevated;
        }
        
        CloseHandle(hToken);
    }
    
    return fRet != FALSE;
}

bool IsRunningAsAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL b = AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup);
    
    if (b) {
        BOOL isMember = FALSE;
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &isMember)) {
            isMember = FALSE;
        }
        
        FreeSid(AdministratorsGroup);
        return isMember;
    }
    
    return false;
}

DWORD GetCurrentProcessId() {
    return ::GetCurrentProcessId();
}

std::wstring GetProcessCommandLine(DWORD processId) {
    std::wstring cmdLine;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    
    if (hProcess) {
        wchar_t path[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;
        
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            cmdLine = path;
        }
        
        CloseHandle(hProcess);
    }
    
    return cmdLine;
}

bool IsProcess64Bit(DWORD processId) {
    BOOL isWow64 = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    
    if (hProcess) {
        IsWow64Process(hProcess, &isWow64);
        CloseHandle(hProcess);
    }
    
    // On 64-bit Windows, if the process is not running under WOW64, it's a 64-bit process
    return !isWow64 && Is64BitOperatingSystem();
}

bool Is64BitOperatingSystem() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
           si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
}

bool InjectDLL(DWORD processId, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT, PAGE_READWRITE);
    
    if (!pRemotePath) {
        CloseHandle(hProcess);
        return false;
    }
    
    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath.c_str(), dllPathSize, NULL)) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)pLoadLibraryW, 
                                       pRemotePath, 0, NULL);
    
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return exitCode != 0;
}

bool CreateProcessAndInject(const std::wstring& applicationPath, const std::wstring& dllPath, 
                           const std::wstring& commandLine) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    
    std::wstring fullCommandLine = L"\"" + applicationPath + L"\" " + commandLine;
    
    // Create a copy of the command line since CreateProcessW may modify it
    std::vector<wchar_t> cmdLine(fullCommandLine.begin(), fullCommandLine.end());
    cmdLine.push_back(L'\0');
    
    if (!CreateProcessW(NULL, cmdLine.data(), NULL, NULL, FALSE, 
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }
    
    bool result = InjectDLL(pi.dwProcessId, dllPath);
    
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return result;
}

// Logging utilities
Logger::Logger(const std::wstring& logFilePath)
    : logFilePath_(logFilePath), logLevel_(LogLevel::INFO), logCallback_(nullptr) {
}

Logger::~Logger() {
}

void Logger::SetLogFile(const std::wstring& logFilePath) {
    std::lock_guard<std::mutex> lock(logMutex_);
    logFilePath_ = logFilePath;
}

void Logger::SetLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex_);
    logLevel_ = level;
}

void Logger::SetLogCallback(LogCallback callback) {
    std::lock_guard<std::mutex> lock(logMutex_);
    logCallback_ = callback;
}

void Logger::Debug(const std::wstring& message) {
    Log(LogLevel::DEBUG, message);
}

void Logger::Info(const std::wstring& message) {
    Log(LogLevel::INFO, message);
}

void Logger::Warning(const std::wstring& message) {
    Log(LogLevel::WARNING, message);
}

void Logger::Error(const std::wstring& message) {
    Log(LogLevel::ERROR, message);
}

void Logger::Critical(const std::wstring& message) {
    Log(LogLevel::CRITICAL, message);
}

void Logger::Log(LogLevel level, const std::wstring& message) {
    if (level < logLevel_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(logMutex_);
    std::wstring formattedMessage = FormatLogMessage(level, message);
    
    if (logCallback_) {
        logCallback_(formattedMessage);
    }
    
    if (!logFilePath_.empty()) {
        std::wofstream file(logFilePath_, std::ios::app);
        if (file.is_open()) {
            file << formattedMessage << std::endl;
        }
    }
    
    // Also output to debug console
    DebugPrint(formattedMessage);
}

std::wstring Logger::FormatLogMessage(LogLevel level, const std::wstring& message) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::wstringstream ss;
    ss << std::put_time(std::localtime(&time), L"[%Y-%m-%d %H:%M:%S] ");
    ss << L"[" << LogLevelToString(level) << L"] ";
    ss << message;
    
    return ss.str();
}

std::wstring Logger::LogLevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::DEBUG:
        return L"DEBUG";
    case LogLevel::INFO:
        return L"INFO";
    case LogLevel::WARNING:
        return L"WARNING";
    case LogLevel::ERROR:
        return L"ERROR";
    case LogLevel::CRITICAL:
        return L"CRITICAL";
    default:
        return L"UNKNOWN";
    }
}

} // namespace Utilities
} // namespace CS2Injector 