#pragma once

#include <Windows.h>
#include <string>
#include <map>
#include <vector>

// Forward declaration
namespace CS2Injector {
    enum class InjectionMethod;
}

class ConfigManager {
public:
    // Singleton instance
    static ConfigManager& GetInstance();
    
    // Initialize with default configuration
    bool Initialize();
    
    // Load configuration from file
    bool LoadConfig(const std::wstring& configFile = L"");
    
    // Save configuration to file
    bool SaveConfig(const std::wstring& configFile = L"");
    
    // Get/set DLL path
    std::wstring GetDllPath() const;
    void SetDllPath(const std::wstring& dllPath);
    
    // Get/set process name
    std::wstring GetProcessName() const;
    void SetProcessName(const std::wstring& processName);
    
    // Get/set injection method
    CS2Injector::InjectionMethod GetInjectionMethod() const;
    void SetInjectionMethod(CS2Injector::InjectionMethod method);
    
    // Get/set silent mode
    bool GetSilentMode() const;
    void SetSilentMode(bool silent);
    
    // Get/set close delay
    DWORD GetCloseDelay() const;
    void SetCloseDelay(DWORD delay);
    
    // Get/set randomization
    bool GetUseRandomization() const;
    void SetUseRandomization(bool useRandomization);
    
    // Get/set cleanup PE headers
    bool GetCleanupPEHeaders() const;
    void SetCleanupPEHeaders(bool cleanup);
    
    // Get/set evasion techniques
    bool GetUseEvasionTechniques() const;
    void SetUseEvasionTechniques(bool useEvasion);
    
    // Get/set wait for exit
    bool GetWaitForExit() const;
    void SetWaitForExit(bool wait);
    
    // Get/set timeout
    DWORD GetTimeout() const;
    void SetTimeout(DWORD timeout);
    
    // Get/set auto inject
    bool GetAutoInject() const;
    void SetAutoInject(bool autoInject);
    
    // Get/set minimize to tray
    bool GetMinimizeToTray() const;
    void SetMinimizeToTray(bool minimizeToTray);
    
    // Get/set start with Windows
    bool GetStartWithWindows() const;
    void SetStartWithWindows(bool startWithWindows);
    
    // Get/set hide console
    bool GetHideConsole() const;
    void SetHideConsole(bool hideConsole);
    
    // Get/set theme
    std::wstring GetTheme() const;
    void SetTheme(const std::wstring& theme);
    
    // Get available themes
    std::vector<std::wstring> GetAvailableThemes() const;
    
private:
    // Private constructor for singleton
    ConfigManager();
    
    // Prevent copying
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    // Default config file
    std::wstring configFile_;
    
    // Configuration values
    std::wstring dllPath_;
    std::wstring processName_;
    CS2Injector::InjectionMethod injectionMethod_;
    bool silentMode_;
    DWORD closeDelay_;
    bool useRandomization_;
    bool cleanupPEHeaders_;
    bool useEvasionTechniques_;
    bool waitForExit_;
    DWORD timeout_;
    bool autoInject_;
    bool minimizeToTray_;
    bool startWithWindows_;
    bool hideConsole_;
    std::wstring theme_;
    
    // Read a string value from INI
    std::wstring ReadString(const std::wstring& section, const std::wstring& key, const std::wstring& defaultValue);
    
    // Read an integer value from INI
    int ReadInt(const std::wstring& section, const std::wstring& key, int defaultValue);
    
    // Write a string value to INI
    bool WriteString(const std::wstring& section, const std::wstring& key, const std::wstring& value);
    
    // Write an integer value to INI
    bool WriteInt(const std::wstring& section, const std::wstring& key, int value);
    
    // Set default values
    void SetDefaults();
    
    // Check if the file exists
    bool FileExists(const std::wstring& filePath);
}; 