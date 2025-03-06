#include <Windows.h>
#include <CommCtrl.h>
#include <shellapi.h>
#include <string>
#include "UIManager.h"
#include "ConfigManager.h"

// Link with Common Controls library
#pragma comment(lib, "comctl32.lib")

// Enable Visual Styles
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Check if another instance is already running
bool IsAnotherInstanceRunning() {
    HANDLE hMutex = CreateMutex(NULL, TRUE, L"CS2Injector_Singleton_Mutex");
    return (GetLastError() == ERROR_ALREADY_EXISTS);
}

// Check if this process has administrative privileges
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    
    return isAdmin != FALSE;
}

// Entry point
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);
    
    // Check if another instance is already running
    if (IsAnotherInstanceRunning()) {
        // Find the other instance
        HWND hOtherWnd = FindWindow(L"CS2Injector_Window_Class", NULL);
        
        if (hOtherWnd) {
            // If window is iconic (minimized), restore it
            if (IsIconic(hOtherWnd)) {
                ShowWindow(hOtherWnd, SW_RESTORE);
            }
            
            // Bring window to foreground
            SetForegroundWindow(hOtherWnd);
            
            // Process command line to see if we need to inject
            if (wcslen(lpCmdLine) > 0) {
                // TODO: Send command line to existing window via WM_COPYDATA
            }
        }
        
        return 0;
    }
    
    // Check if running as admin
    if (!IsRunningAsAdmin()) {
        // Re-launch with admin rights
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = L"CS2Injector.exe";
        sei.lpParameters = lpCmdLine;
        sei.nShow = nCmdShow;
        
        if (ShellExecuteEx(&sei)) {
            return 0;
        }
        
        // Show error message if failed to elevate
        MessageBox(NULL, L"This application requires administrative privileges to run.", 
            L"CS2 Injector", MB_ICONERROR | MB_OK);
        return 1;
    }
    
    // Initialize configuration
    if (!ConfigManager::GetInstance().Initialize()) {
        MessageBox(NULL, L"Failed to initialize configuration.", L"CS2 Injector", MB_ICONERROR | MB_OK);
        return 1;
    }
    
    // Load configuration
    if (!ConfigManager::GetInstance().LoadConfig()) {
        // Create default configuration if loading fails
        ConfigManager::GetInstance().SaveConfig();
    }
    
    // Initialize UI
    UIManager& uiManager = UIManager::GetInstance();
    if (!uiManager.Initialize(hInstance, nCmdShow)) {
        MessageBox(NULL, L"Failed to initialize user interface.", L"CS2 Injector", MB_ICONERROR | MB_OK);
        return 1;
    }
    
    // Process command line arguments
    if (wcslen(lpCmdLine) > 0) {
        // Parse command line arguments
        int numArgs;
        LPWSTR* args = CommandLineToArgvW(lpCmdLine, &numArgs);
        
        if (args) {
            // Process each argument
            for (int i = 0; i < numArgs; i++) {
                if (wcscmp(args[i], L"-inject") == 0) {
                    // Auto-inject at startup
                    uiManager.InjectDLL();
                }
                else if (wcscmp(args[i], L"-process") == 0 && i + 1 < numArgs) {
                    // Set process name
                    uiManager.SetProcessName(args[i + 1]);
                    i++; // Skip the next argument
                }
                else if (wcscmp(args[i], L"-dll") == 0 && i + 1 < numArgs) {
                    // Set DLL path
                    uiManager.SetDllPath(args[i + 1]);
                    i++; // Skip the next argument
                }
                else if (wcscmp(args[i], L"-method") == 0 && i + 1 < numArgs) {
                    // Set injection method
                    int method = _wtoi(args[i + 1]);
                    uiManager.SetInjectionMethod(static_cast<CS2Injector::InjectionMethod>(method));
                    i++; // Skip the next argument
                }
                else if (wcscmp(args[i], L"-silent") == 0) {
                    // Enable silent mode
                    ConfigManager::GetInstance().SetSilentMode(true);
                }
                else if (wcscmp(args[i], L"-minimize") == 0) {
                    // Start minimized
                    ShowWindow(uiManager.GetWindowHandle(), SW_MINIMIZE);
                }
                else if (wcscmp(args[i], L"-exit") == 0) {
                    // Exit after injection
                    uiManager.InjectDLL();
                    uiManager.Exit();
                    return 0;
                }
            }
            
            LocalFree(args);
        }
    }
    
    // Apply settings from configuration
    uiManager.ApplySettings();
    
    // Run the message loop
    return uiManager.Run();
} 