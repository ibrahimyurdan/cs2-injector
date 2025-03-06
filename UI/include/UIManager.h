#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include "ConfigManager.h"

// Forward declarations
typedef struct HWND__ *HWND;
typedef struct HMENU__ *HMENU;
typedef struct HICON__ *HICON;
typedef unsigned int UINT;

namespace CS2Injector {
    enum class InjectionError;
    struct ProcessInfo;
    enum class InjectionMethod;
}

// Callback for status updates
using StatusCallback = std::function<void(const std::wstring&)>;

// GUI window styles
enum class WindowStyle {
    DEFAULT,
    DARK,
    LIGHT,
    MINIMALIST,
    CUSTOM
};

class UIManager {
public:
    // Singleton instance
    static UIManager& GetInstance();
    
    // Initialize the UI
    bool Initialize(HINSTANCE hInstance, int nCmdShow);
    
    // Run the message loop
    int Run();
    
    // Register the window class
    bool RegisterWindowClass(HINSTANCE hInstance);
    
    // Create the main window
    bool CreateMainWindow(HINSTANCE hInstance, int nCmdShow);
    
    // Create child controls
    void CreateControls();
    
    // Add a status message
    void AddStatusMessage(const std::wstring& message);
    
    // Set status callback
    void SetStatusCallback(StatusCallback callback);
    
    // Update process list
    void UpdateProcessList();
    
    // Inject DLL
    bool InjectDLL();
    
    // Select DLL file via dialog
    void SelectDLLFile();
    
    // Refresh status
    void RefreshStatus();
    
    // Get window handle
    HWND GetWindowHandle() const;
    
    // Show error message
    void ShowError(const std::wstring& message);
    
    // Show information message
    void ShowInfo(const std::wstring& message);
    
    // Show confirmation dialog
    bool ShowConfirmation(const std::wstring& message);
    
    // Handle WM_COMMAND messages
    void HandleCommand(WORD command);
    
    // Handle WM_NOTIFY messages
    void HandleNotify(LPARAM lParam);
    
    // Handle settings dialog
    void ShowSettingsDialog();
    
    // Handle about dialog
    void ShowAboutDialog();
    
    // Handle tray icon
    void HandleTrayIcon(LPARAM lParam);
    
    // Create tray icon
    void CreateTrayIcon();
    
    // Remove tray icon
    void RemoveTrayIcon();
    
    // Minimize to tray
    void MinimizeToTray();
    
    // Restore from tray
    void RestoreFromTray();
    
    // Set window style
    void SetWindowStyle(WindowStyle style);
    
    // Set custom colors
    void SetCustomColors(COLORREF background, COLORREF text, COLORREF accent);
    
    // Apply settings from config
    void ApplySettings();
    
    // Initialize injection process
    bool InitializeInjection();
    
    // Set process name
    void SetProcessName(const std::wstring& processName);
    
    // Get process name
    std::wstring GetProcessName() const;
    
    // Set DLL path
    void SetDllPath(const std::wstring& dllPath);
    
    // Get DLL path
    std::wstring GetDllPath() const;
    
    // Set injection method
    void SetInjectionMethod(CS2Injector::InjectionMethod method);
    
    // Get injection method
    CS2Injector::InjectionMethod GetInjectionMethod() const;
    
    // Check if process is running
    bool IsProcessRunning() const;
    
    // Set window title
    void SetWindowTitle(const std::wstring& title);
    
    // Set status text
    void SetStatusText(const std::wstring& status);
    
    // Exit application
    void Exit();
    
private:
    // Private constructor for singleton
    UIManager();
    
    // Prevent copying
    UIManager(const UIManager&) = delete;
    UIManager& operator=(const UIManager&) = delete;
    
    // Window handles
    HWND hWnd_;                 // Main window
    HWND hProcessCombo_;        // Process combo box
    HWND hDllPathEdit_;         // DLL path edit
    HWND hBrowseButton_;        // Browse button
    HWND hMethodCombo_;         // Injection method combo box
    HWND hInjectButton_;        // Inject button
    HWND hRefreshButton_;       // Refresh button
    HWND hStatusText_;          // Status text
    HWND hSettingsButton_;      // Settings button
    HWND hAboutButton_;         // About button
    HWND hExitButton_;          // Exit button
    
    // Resources
    HICON hIcon_;               // Application icon
    HMENU hMenu_;               // Main menu
    HMENU hTrayMenu_;           // Tray menu
    
    // Tray icon data
    NOTIFYICONDATA nid_;
    bool isTrayIconCreated_;
    
    // UI state
    bool isMinimized_;
    WindowStyle windowStyle_;
    COLORREF backgroundColor_;
    COLORREF textColor_;
    COLORREF accentColor_;
    
    // Process list
    std::vector<CS2Injector::ProcessInfo> processList_;
    
    // Status callback
    StatusCallback statusCallback_;
    
    // Buffer for status
    std::wstring statusText_;
    
    // Window procedure
    static LRESULT CALLBACK WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    
    // Settings dialog procedure
    static INT_PTR CALLBACK SettingsDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    
    // About dialog procedure
    static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    
    // Helper to handle injection
    void HandleInjectionResult(CS2Injector::InjectionError result);
    
    // Set control fonts
    void SetControlFonts();
    
    // Create window styles
    void CreateStyles();
    
    // Apply window style
    void ApplyWindowStyle();
    
    // Position controls
    void PositionControls();
    
    // Create brushes for custom drawing
    void CreateBrushes();
    
    // Delete brushes for custom drawing
    void DeleteBrushes();
    
    // Draw controls with custom style
    void DrawControls(HDC hdc);
    
    // Custom drawing procedures
    void DrawButton(HDC hdc, HWND hButton);
    void DrawEdit(HDC hdc, HWND hEdit);
    void DrawComboBox(HDC hdc, HWND hCombo);
    void DrawStatusText(HDC hdc);
    
    // Custom brushes
    HBRUSH hBackgroundBrush_;
    HBRUSH hButtonBrush_;
    HBRUSH hEditBrush_;
    HBRUSH hComboBoxBrush_;
    
    // Custom fonts
    HFONT hTitleFont_;
    HFONT hNormalFont_;
    HFONT hButtonFont_;
    HFONT hStatusFont_;
}; 