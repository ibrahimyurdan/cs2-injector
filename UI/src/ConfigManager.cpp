#include "../include/ConfigManager.h"
#include "../../Common/include/Definitions.h"

#include <fstream>
#include <filesystem>
#include <Shlobj.h>

// Singleton instance
ConfigManager& ConfigManager::GetInstance() {
    static ConfigManager instance;
    return instance;
}

// Private constructor for singleton
ConfigManager::ConfigManager() {
    // Set default configuration file path
    wchar_t appDataPath[MAX_PATH] = { 0 };
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        configFile_ = std::wstring(appDataPath) + L"\\CS2Injector\\CS2Injector.ini";
    } else {
        // Fall back to current directory
        configFile_ = L"CS2Injector.ini";
    }
    
    // Set default values
    SetDefaults();
}

// Initialize with default configuration
bool ConfigManager::Initialize() {
    // Create directory for config file if it doesn't exist
    std::filesystem::path configPath = configFile_;
    std::filesystem::path configDir = configPath.parent_path();
    
    try {
        if (!std::filesystem::exists(configDir)) {
            std::filesystem::create_directories(configDir);
        }
    } catch (const std::exception&) {
        return false;
    }
    
    // If config file doesn't exist, create it with default values
    if (!FileExists(configFile_)) {
        return SaveConfig();
    }
    
    return true;
}

// Load configuration from file
bool ConfigManager::LoadConfig(const std::wstring& configFile) {
    // If custom config file is provided, use it
    if (!configFile.empty()) {
        configFile_ = configFile;
    }
    
    // Check if the file exists
    if (!FileExists(configFile_)) {
        return false;
    }
    
    // Read values from the INI file
    dllPath_ = ReadString(L"Settings", L"DllPath", dllPath_);
    processName_ = ReadString(L"Settings", L"ProcessName", processName_);
    injectionMethod_ = static_cast<CS2Injector::InjectionMethod>(ReadInt(L"Settings", L"InjectionMethod", static_cast<int>(injectionMethod_)));
    silentMode_ = ReadInt(L"Settings", L"SilentMode", silentMode_ ? 1 : 0) != 0;
    closeDelay_ = ReadInt(L"Settings", L"CloseDelay", closeDelay_);
    useRandomization_ = ReadInt(L"Settings", L"UseRandomization", useRandomization_ ? 1 : 0) != 0;
    cleanupPEHeaders_ = ReadInt(L"Settings", L"CleanupPEHeaders", cleanupPEHeaders_ ? 1 : 0) != 0;
    useEvasionTechniques_ = ReadInt(L"Settings", L"UseEvasionTechniques", useEvasionTechniques_ ? 1 : 0) != 0;
    waitForExit_ = ReadInt(L"Settings", L"WaitForExit", waitForExit_ ? 1 : 0) != 0;
    timeout_ = ReadInt(L"Settings", L"Timeout", timeout_);
    autoInject_ = ReadInt(L"Settings", L"AutoInject", autoInject_ ? 1 : 0) != 0;
    minimizeToTray_ = ReadInt(L"Settings", L"MinimizeToTray", minimizeToTray_ ? 1 : 0) != 0;
    startWithWindows_ = ReadInt(L"Settings", L"StartWithWindows", startWithWindows_ ? 1 : 0) != 0;
    hideConsole_ = ReadInt(L"Settings", L"HideConsole", hideConsole_ ? 1 : 0) != 0;
    theme_ = ReadString(L"Settings", L"Theme", theme_);
    
    return true;
}

// Save configuration to file
bool ConfigManager::SaveConfig(const std::wstring& configFile) {
    // If custom config file is provided, use it
    if (!configFile.empty()) {
        configFile_ = configFile;
    }
    
    // Write values to the INI file
    bool success = true;
    success &= WriteString(L"Settings", L"DllPath", dllPath_);
    success &= WriteString(L"Settings", L"ProcessName", processName_);
    success &= WriteInt(L"Settings", L"InjectionMethod", static_cast<int>(injectionMethod_));
    success &= WriteInt(L"Settings", L"SilentMode", silentMode_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"CloseDelay", closeDelay_);
    success &= WriteInt(L"Settings", L"UseRandomization", useRandomization_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"CleanupPEHeaders", cleanupPEHeaders_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"UseEvasionTechniques", useEvasionTechniques_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"WaitForExit", waitForExit_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"Timeout", timeout_);
    success &= WriteInt(L"Settings", L"AutoInject", autoInject_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"MinimizeToTray", minimizeToTray_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"StartWithWindows", startWithWindows_ ? 1 : 0);
    success &= WriteInt(L"Settings", L"HideConsole", hideConsole_ ? 1 : 0);
    success &= WriteString(L"Settings", L"Theme", theme_);
    
    return success;
}

// Get/set DLL path
std::wstring ConfigManager::GetDllPath() const {
    return dllPath_;
}

void ConfigManager::SetDllPath(const std::wstring& dllPath) {
    dllPath_ = dllPath;
}

// Get/set process name
std::wstring ConfigManager::GetProcessName() const {
    return processName_;
}

void ConfigManager::SetProcessName(const std::wstring& processName) {
    processName_ = processName;
}

// Get/set injection method
CS2Injector::InjectionMethod ConfigManager::GetInjectionMethod() const {
    return injectionMethod_;
}

void ConfigManager::SetInjectionMethod(CS2Injector::InjectionMethod method) {
    injectionMethod_ = method;
}

// Get/set silent mode
bool ConfigManager::GetSilentMode() const {
    return silentMode_;
}

void ConfigManager::SetSilentMode(bool silent) {
    silentMode_ = silent;
}

// Get/set close delay
DWORD ConfigManager::GetCloseDelay() const {
    return closeDelay_;
}

void ConfigManager::SetCloseDelay(DWORD delay) {
    closeDelay_ = delay;
}

// Get/set randomization
bool ConfigManager::GetUseRandomization() const {
    return useRandomization_;
}

void ConfigManager::SetUseRandomization(bool useRandomization) {
    useRandomization_ = useRandomization;
}

// Get/set cleanup PE headers
bool ConfigManager::GetCleanupPEHeaders() const {
    return cleanupPEHeaders_;
}

void ConfigManager::SetCleanupPEHeaders(bool cleanup) {
    cleanupPEHeaders_ = cleanup;
}

// Get/set evasion techniques
bool ConfigManager::GetUseEvasionTechniques() const {
    return useEvasionTechniques_;
}

void ConfigManager::SetUseEvasionTechniques(bool useEvasion) {
    useEvasionTechniques_ = useEvasion;
}

// Get/set wait for exit
bool ConfigManager::GetWaitForExit() const {
    return waitForExit_;
}

void ConfigManager::SetWaitForExit(bool wait) {
    waitForExit_ = wait;
}

// Get/set timeout
DWORD ConfigManager::GetTimeout() const {
    return timeout_;
}

void ConfigManager::SetTimeout(DWORD timeout) {
    timeout_ = timeout;
}

// Get/set auto inject
bool ConfigManager::GetAutoInject() const {
    return autoInject_;
}

void ConfigManager::SetAutoInject(bool autoInject) {
    autoInject_ = autoInject;
}

// Get/set minimize to tray
bool ConfigManager::GetMinimizeToTray() const {
    return minimizeToTray_;
}

void ConfigManager::SetMinimizeToTray(bool minimizeToTray) {
    minimizeToTray_ = minimizeToTray;
}

// Get/set start with Windows
bool ConfigManager::GetStartWithWindows() const {
    return startWithWindows_;
}

void ConfigManager::SetStartWithWindows(bool startWithWindows) {
    startWithWindows_ = startWithWindows;
    
    // Update registry for startup
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (startWithWindows) {
            // Get executable path
            wchar_t exePath[MAX_PATH] = { 0 };
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            
            // Add to startup
            RegSetValueExW(hKey, L"CS2Injector", 0, REG_SZ, (BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
        } else {
            // Remove from startup
            RegDeleteValueW(hKey, L"CS2Injector");
        }
        
        RegCloseKey(hKey);
    }
}

// Get/set hide console
bool ConfigManager::GetHideConsole() const {
    return hideConsole_;
}

void ConfigManager::SetHideConsole(bool hideConsole) {
    hideConsole_ = hideConsole;
}

// Get/set theme
std::wstring ConfigManager::GetTheme() const {
    return theme_;
}

void ConfigManager::SetTheme(const std::wstring& theme) {
    theme_ = theme;
}

// Get available themes
std::vector<std::wstring> ConfigManager::GetAvailableThemes() const {
    return { L"Light", L"Dark", L"System" };
}

// Read a string value from INI
std::wstring ConfigManager::ReadString(const std::wstring& section, const std::wstring& key, const std::wstring& defaultValue) {
    wchar_t buffer[1024] = { 0 };
    GetPrivateProfileStringW(section.c_str(), key.c_str(), defaultValue.c_str(), buffer, sizeof(buffer) / sizeof(wchar_t), configFile_.c_str());
    return buffer;
}

// Read an integer value from INI
int ConfigManager::ReadInt(const std::wstring& section, const std::wstring& key, int defaultValue) {
    return GetPrivateProfileIntW(section.c_str(), key.c_str(), defaultValue, configFile_.c_str());
}

// Write a string value to INI
bool ConfigManager::WriteString(const std::wstring& section, const std::wstring& key, const std::wstring& value) {
    return WritePrivateProfileStringW(section.c_str(), key.c_str(), value.c_str(), configFile_.c_str()) != 0;
}

// Write an integer value to INI
bool ConfigManager::WriteInt(const std::wstring& section, const std::wstring& key, int value) {
    wchar_t valueStr[16] = { 0 };
    _itow_s(value, valueStr, 10);
    return WritePrivateProfileStringW(section.c_str(), key.c_str(), valueStr, configFile_.c_str()) != 0;
}

// Set default values
void ConfigManager::SetDefaults() {
    dllPath_ = L"payload.dll";
    processName_ = DEFAULT_PROCESS_NAME;
    injectionMethod_ = CS2Injector::InjectionMethod::MANUAL_MAP;
    silentMode_ = DEFAULT_SILENT_MODE != 0;
    closeDelay_ = DEFAULT_CLOSE_DELAY;
    useRandomization_ = true;
    cleanupPEHeaders_ = true;
    useEvasionTechniques_ = true;
    waitForExit_ = true;
    timeout_ = 5000;
    autoInject_ = false;
    minimizeToTray_ = true;
    startWithWindows_ = false;
    hideConsole_ = true;
    theme_ = L"Dark";
}

// Check if the file exists
bool ConfigManager::FileExists(const std::wstring& filePath) {
    DWORD attributes = GetFileAttributesW(filePath.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY));
} 