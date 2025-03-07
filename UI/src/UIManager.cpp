#include "../include/UIManager.h"
#include "../include/ConfigManager.h"
#include "../../Library/include/Injector.h"
#include "../../Common/include/Definitions.h"
#include "../resources/resource.h"
#include <commctrl.h>
#include <shellapi.h>

// Window class name
#define WINDOW_CLASS_NAME       L"CS2Injector_Window_Class"

// Singleton instance
UIManager& UIManager::GetInstance() {
    static UIManager instance;
    return instance;
}

// Private constructor
UIManager::UIManager()
    : hWnd_(NULL), hProcessCombo_(NULL), hDllPathEdit_(NULL), hBrowseButton_(NULL),
    hMethodCombo_(NULL), hInjectButton_(NULL), hRefreshButton_(NULL), hStatusText_(NULL),
    hSettingsButton_(NULL), hAboutButton_(NULL), hExitButton_(NULL), hIcon_(NULL),
    hMenu_(NULL), hTrayMenu_(NULL), isTrayIconCreated_(false), isMinimized_(false),
    windowStyle_(WindowStyle::DARK), backgroundColor_(RGB(32, 32, 32)), textColor_(RGB(240, 240, 240)),
    accentColor_(RGB(0, 120, 215)), hBackgroundBrush_(NULL), hButtonBrush_(NULL),
    hEditBrush_(NULL), hComboBoxBrush_(NULL), hTitleFont_(NULL), hNormalFont_(NULL),
    hButtonFont_(NULL), hStatusFont_(NULL) {
}

// Initialize the UI
bool UIManager::Initialize(HINSTANCE hInstance, int nCmdShow) {
    // Register window class
    if (!RegisterWindowClass(hInstance)) {
        return false;
    }
    
    // Create main window
    if (!CreateMainWindow(hInstance, nCmdShow)) {
        return false;
    }
    
    // Create controls
    CreateControls();
    
    // Set up fonts and styles
    SetControlFonts();
    CreateStyles();
    ApplyWindowStyle();
    
    // Update process list
    UpdateProcessList();
    
    // Create tray icon if minimized to tray is enabled
    if (ConfigManager::GetInstance().GetMinimizeToTray()) {
        CreateTrayIcon();
    }
    
    // Set default status
    SetStatusText(L"Ready");
    
    return true;
}

// Register the window class
bool UIManager::RegisterWindowClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex = { 0 };
    
    // Load icon
    hIcon_ = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    if (!hIcon_) {
        // Use default icon if resource not found
        hIcon_ = LoadIcon(NULL, IDI_APPLICATION);
    }
    
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WindowProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = hIcon_;
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDR_MAINMENU);
    wcex.lpszClassName = WINDOW_CLASS_NAME;
    wcex.hIconSm = hIcon_;
    
    return RegisterClassExW(&wcex) != 0;
}

// Create main window
bool UIManager::CreateMainWindow(HINSTANCE hInstance, int nCmdShow) {
    // Load menu
    hMenu_ = LoadMenu(hInstance, MAKEINTRESOURCEW(IDR_MAINMENU));
    
    // Create the main window
    hWnd_ = CreateWindowExW(0, WINDOW_CLASS_NAME, L"CS2 Injector",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 600, 400,
        NULL, hMenu_, hInstance, NULL);
    
    if (!hWnd_) {
        return false;
    }
    
    // Store this pointer with the window
    SetWindowLongPtrW(hWnd_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    
    // Show window
    ShowWindow(hWnd_, nCmdShow);
    UpdateWindow(hWnd_);
    
    return true;
}

// Window procedure
LRESULT CALLBACK UIManager::WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    // Get the UIManager instance
    UIManager* pThis = reinterpret_cast<UIManager*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    
    switch (message) {
    case WM_COMMAND:
        if (pThis) {
            pThis->HandleCommand(LOWORD(wParam));
        }
        break;
    
    case WM_NOTIFY:
        if (pThis) {
            pThis->HandleNotify(lParam);
        }
        break;
    
    case WM_TRAYICON:
        if (pThis) {
            pThis->HandleTrayIcon(lParam);
        }
        break;
    
    case WM_SIZE:
        if (pThis) {
            if (wParam == SIZE_MINIMIZED && ConfigManager::GetInstance().GetMinimizeToTray()) {
                pThis->MinimizeToTray();
            } else {
                pThis->PositionControls();
            }
        }
        break;
    
    case WM_CLOSE:
        if (pThis) {
            pThis->Exit();
        }
        return 0;
    
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    
    default:
        return DefWindowProcW(hWnd, message, wParam, lParam);
    }
    
    return 0;
}

// Run the message loop
int UIManager::Run() {
    MSG msg;
    
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(hWnd_, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    
    return (int)msg.wParam;
}

// Get window handle
HWND UIManager::GetWindowHandle() const {
    return hWnd_;
}

// Exit application
void UIManager::Exit() {
    // Remove tray icon if created
    if (isTrayIconCreated_) {
        RemoveTrayIcon();
    }
    
    // Delete brushes and fonts
    DeleteBrushes();
    
    // Close the window
    DestroyWindow(hWnd_);
}

// Create the basic controls
void UIManager::CreateControls() {
    HINSTANCE hInstance = (HINSTANCE)GetWindowLongPtr(hWnd_, GWLP_HINSTANCE);
    
    // Create process combo box
    hProcessCombo_ = CreateWindowEx(0, WC_COMBOBOX, NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST,
        20, 20, 300, 200, hWnd_, (HMENU)IDC_PROCESS_COMBO, hInstance, NULL);
    
    // Create DLL path edit box
    hDllPathEdit_ = CreateWindowEx(0, WC_EDIT, NULL,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        20, 60, 250, 24, hWnd_, (HMENU)IDC_DLL_PATH_EDIT, hInstance, NULL);
    
    // Create browse button
    hBrowseButton_ = CreateWindowEx(0, WC_BUTTON, L"Browse...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        280, 60, 80, 24, hWnd_, (HMENU)IDC_BROWSE_BUTTON, hInstance, NULL);
    
    // Create method combo box
    hMethodCombo_ = CreateWindowEx(0, WC_COMBOBOX, NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST,
        20, 100, 200, 200, hWnd_, (HMENU)IDC_METHOD_COMBO, hInstance, NULL);
    
    // Create inject button
    hInjectButton_ = CreateWindowEx(0, WC_BUTTON, L"Inject",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 140, 100, 30, hWnd_, (HMENU)IDC_INJECT_BUTTON, hInstance, NULL);
    
    // Create refresh button
    hRefreshButton_ = CreateWindowEx(0, WC_BUTTON, L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        130, 140, 100, 30, hWnd_, (HMENU)IDC_REFRESH_BUTTON, hInstance, NULL);
    
    // Create status text
    hStatusText_ = CreateWindowEx(0, WC_STATIC, L"Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 190, 560, 20, hWnd_, (HMENU)IDC_STATUS_TEXT, hInstance, NULL);
    
    // Create settings button
    hSettingsButton_ = CreateWindowEx(0, WC_BUTTON, L"Settings",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 230, 100, 30, hWnd_, (HMENU)IDC_SETTINGS_BUTTON, hInstance, NULL);
    
    // Create about button
    hAboutButton_ = CreateWindowEx(0, WC_BUTTON, L"About",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        130, 230, 100, 30, hWnd_, (HMENU)IDC_ABOUT_BUTTON, hInstance, NULL);
    
    // Create exit button
    hExitButton_ = CreateWindowEx(0, WC_BUTTON, L"Exit",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        240, 230, 100, 30, hWnd_, (HMENU)IDC_EXIT_BUTTON, hInstance, NULL);
    
    // Set default values for controls
    SetWindowText(hDllPathEdit_, ConfigManager::GetInstance().GetDllPath().c_str());
    
    // Populate method combo box
    SendMessage(hMethodCombo_, CB_ADDSTRING, 0, (LPARAM)L"LoadLibrary");
    SendMessage(hMethodCombo_, CB_ADDSTRING, 0, (LPARAM)L"Manual Mapping");
    SendMessage(hMethodCombo_, CB_ADDSTRING, 0, (LPARAM)L"Thread Hijacking");
    SendMessage(hMethodCombo_, CB_ADDSTRING, 0, (LPARAM)L"Shellcode Injection");
    
    // Set default method from config
    SendMessage(hMethodCombo_, CB_SETCURSEL, 
                static_cast<WPARAM>(ConfigManager::GetInstance().GetInjectionMethod()), 
                0);
}

// Set control fonts (to be implemented)
void UIManager::SetControlFonts() {
    // Create fonts
    hNormalFont_ = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
        ANSI_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    
    hButtonFont_ = CreateFont(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, 
        ANSI_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    
    hTitleFont_ = CreateFont(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, 
        ANSI_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    
    hStatusFont_ = CreateFont(14, 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE, 
        ANSI_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    
    // Set fonts for controls
    SendMessage(hProcessCombo_, WM_SETFONT, (WPARAM)hNormalFont_, TRUE);
    SendMessage(hDllPathEdit_, WM_SETFONT, (WPARAM)hNormalFont_, TRUE);
    SendMessage(hBrowseButton_, WM_SETFONT, (WPARAM)hButtonFont_, TRUE);
    SendMessage(hMethodCombo_, WM_SETFONT, (WPARAM)hNormalFont_, TRUE);
    SendMessage(hInjectButton_, WM_SETFONT, (WPARAM)hButtonFont_, TRUE);
    SendMessage(hRefreshButton_, WM_SETFONT, (WPARAM)hButtonFont_, TRUE);
    SendMessage(hStatusText_, WM_SETFONT, (WPARAM)hStatusFont_, TRUE);
    SendMessage(hSettingsButton_, WM_SETFONT, (WPARAM)hButtonFont_, TRUE);
    SendMessage(hAboutButton_, WM_SETFONT, (WPARAM)hButtonFont_, TRUE);
    SendMessage(hExitButton_, WM_SETFONT, (WPARAM)hButtonFont_, TRUE);
}

// Create window styles (to be implemented)
void UIManager::CreateStyles() {
    // Create brushes
    CreateBrushes();
}

// Apply window style (to be implemented)
void UIManager::ApplyWindowStyle() {
    // Set window style based on theme
    std::wstring theme = ConfigManager::GetInstance().GetTheme();
    
    if (theme == L"Light") {
        windowStyle_ = WindowStyle::LIGHT;
        backgroundColor_ = RGB(240, 240, 240);
        textColor_ = RGB(0, 0, 0);
        accentColor_ = RGB(0, 120, 215);
    }
    else if (theme == L"Dark") {
        windowStyle_ = WindowStyle::DARK;
        backgroundColor_ = RGB(32, 32, 32);
        textColor_ = RGB(240, 240, 240);
        accentColor_ = RGB(0, 120, 215);
    }
    else { // System
        windowStyle_ = WindowStyle::DEFAULT;
        backgroundColor_ = GetSysColor(COLOR_WINDOW);
        textColor_ = GetSysColor(COLOR_WINDOWTEXT);
        accentColor_ = GetSysColor(COLOR_HIGHLIGHT);
    }
    
    // Delete old brushes
    DeleteBrushes();
    
    // Create brushes with new colors
    CreateBrushes();
    
    // Set window background
    SetClassLongPtr(hWnd_, GCLP_HBRBACKGROUND, (LONG_PTR)hBackgroundBrush_);
    
    // Position controls
    PositionControls();
    
    // Redraw window
    InvalidateRect(hWnd_, NULL, TRUE);
    UpdateWindow(hWnd_);
}

// Position controls (to be implemented)
void UIManager::PositionControls() {
    // Get client area size
    RECT rect;
    GetClientRect(hWnd_, &rect);
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    
    // Position process combo box
    SetWindowPos(hProcessCombo_, NULL, 20, 20, width - 40, 24, SWP_NOZORDER);
    
    // Position DLL path edit box
    SetWindowPos(hDllPathEdit_, NULL, 20, 60, width - 120, 24, SWP_NOZORDER);
    
    // Position browse button
    SetWindowPos(hBrowseButton_, NULL, width - 90, 60, 70, 24, SWP_NOZORDER);
    
    // Position method combo box
    SetWindowPos(hMethodCombo_, NULL, 20, 100, 200, 24, SWP_NOZORDER);
    
    // Position inject button
    SetWindowPos(hInjectButton_, NULL, 20, 140, 100, 30, SWP_NOZORDER);
    
    // Position refresh button
    SetWindowPos(hRefreshButton_, NULL, 130, 140, 100, 30, SWP_NOZORDER);
    
    // Position status text
    SetWindowPos(hStatusText_, NULL, 20, height - 60, width - 40, 20, SWP_NOZORDER);
    
    // Position settings button
    SetWindowPos(hSettingsButton_, NULL, width - 330, height - 30, 100, 25, SWP_NOZORDER);
    
    // Position about button
    SetWindowPos(hAboutButton_, NULL, width - 220, height - 30, 100, 25, SWP_NOZORDER);
    
    // Position exit button
    SetWindowPos(hExitButton_, NULL, width - 110, height - 30, 100, 25, SWP_NOZORDER);
}

// Create tray icon (to be implemented)
void UIManager::CreateTrayIcon() {
    if (isTrayIconCreated_) {
        return;
    }
    
    // Initialize NOTIFYICONDATA
    ZeroMemory(&nid_, sizeof(NOTIFYICONDATA));
    nid_.cbSize = sizeof(NOTIFYICONDATA);
    nid_.hWnd = hWnd_;
    nid_.uID = 1;
    nid_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid_.uCallbackMessage = WM_TRAYICON;
    nid_.hIcon = hIcon_;
    wcscpy_s(nid_.szTip, L"CS2 Injector");
    
    // Add the tray icon
    Shell_NotifyIconW(NIM_ADD, &nid_);
    
    isTrayIconCreated_ = true;
}

// Remove tray icon (to be implemented)
void UIManager::RemoveTrayIcon() {
    if (!isTrayIconCreated_) {
        return;
    }
    
    // Remove the tray icon
    Shell_NotifyIconW(NIM_DELETE, &nid_);
    
    isTrayIconCreated_ = false;
}

// Minimize to tray (to be implemented)
void UIManager::MinimizeToTray() {
    if (!isTrayIconCreated_) {
        CreateTrayIcon();
    }
    
    // Hide the window
    ShowWindow(hWnd_, SW_HIDE);
    isMinimized_ = true;
}

// Delete brushes (to be implemented)
void UIManager::DeleteBrushes() {
    // Delete brushes
    if (hBackgroundBrush_) {
        DeleteObject(hBackgroundBrush_);
        hBackgroundBrush_ = NULL;
    }
    
    if (hButtonBrush_) {
        DeleteObject(hButtonBrush_);
        hButtonBrush_ = NULL;
    }
    
    if (hEditBrush_) {
        DeleteObject(hEditBrush_);
        hEditBrush_ = NULL;
    }
    
    if (hComboBoxBrush_) {
        DeleteObject(hComboBoxBrush_);
        hComboBoxBrush_ = NULL;
    }
    
    // Delete fonts
    if (hNormalFont_) {
        DeleteObject(hNormalFont_);
        hNormalFont_ = NULL;
    }
    
    if (hButtonFont_) {
        DeleteObject(hButtonFont_);
        hButtonFont_ = NULL;
    }
    
    if (hTitleFont_) {
        DeleteObject(hTitleFont_);
        hTitleFont_ = NULL;
    }
    
    if (hStatusFont_) {
        DeleteObject(hStatusFont_);
        hStatusFont_ = NULL;
    }
}

// Update process list
void UIManager::UpdateProcessList() {
    // Clear the combo box
    SendMessage(hProcessCombo_, CB_RESETCONTENT, 0, 0);
    
    // Get process list
    using namespace CS2Injector;
    processList_ = Injector::GetProcessList();
    
    // Add processes to combo box
    for (const auto& process : processList_) {
        int index = static_cast<int>(SendMessage(hProcessCombo_, CB_ADDSTRING, 0, (LPARAM)process.name.c_str()));
        SendMessage(hProcessCombo_, CB_SETITEMDATA, index, (LPARAM)process.id);
    }
    
    // Try to select the process from config
    std::wstring targetProcess = ConfigManager::GetInstance().GetProcessName();
    int count = static_cast<int>(SendMessage(hProcessCombo_, CB_GETCOUNT, 0, 0));
    
    for (int i = 0; i < count; i++) {
        wchar_t processName[MAX_PATH];
        SendMessage(hProcessCombo_, CB_GETLBTEXT, i, (LPARAM)processName);
        
        if (wcscmp(processName, targetProcess.c_str()) == 0) {
            SendMessage(hProcessCombo_, CB_SETCURSEL, i, 0);
            break;
        }
    }
    
    // If no process is selected and there are processes, select the first one
    if (SendMessage(hProcessCombo_, CB_GETCURSEL, 0, 0) == CB_ERR && count > 0) {
        SendMessage(hProcessCombo_, CB_SETCURSEL, 0, 0);
    }
    
    // Update UI state
    BOOL enableControls = (count > 0);
    EnableWindow(hProcessCombo_, enableControls);
    EnableWindow(hInjectButton_, enableControls);
}

// Inject DLL
bool UIManager::InjectDLL() {
    // Get selected process
    int selectedIndex = static_cast<int>(SendMessage(hProcessCombo_, CB_GETCURSEL, 0, 0));
    if (selectedIndex == CB_ERR) {
        ShowError(L"Please select a process to inject into.");
        return false;
    }
    
    DWORD processId = static_cast<DWORD>(SendMessage(hProcessCombo_, CB_GETITEMDATA, selectedIndex, 0));
    
    // Get DLL path
    wchar_t dllPath[MAX_PATH];
    GetWindowText(hDllPathEdit_, dllPath, MAX_PATH);
    
    if (wcslen(dllPath) == 0) {
        ShowError(L"Please select a DLL to inject.");
        return false;
    }
    
    // Check if DLL exists
    if (!ConfigManager::GetInstance().FileExists(dllPath)) {
        ShowError(L"The specified DLL file does not exist.");
        return false;
    }
    
    // Get injection method
    int methodIndex = static_cast<int>(SendMessage(hMethodCombo_, CB_GETCURSEL, 0, 0));
    if (methodIndex == CB_ERR) {
        methodIndex = 0; // Default to LoadLibrary
    }
    
    // Update status
    SetStatusText(L"Injecting...");
    
    // Disable controls during injection
    EnableWindow(hInjectButton_, FALSE);
    EnableWindow(hRefreshButton_, FALSE);
    
    // Create injection options
    CS2Injector::InjectionOptions options;
    options.targetProcess = ConfigManager::GetInstance().GetProcessName();
    options.dllPath = dllPath;
    options.method = static_cast<CS2Injector::InjectionMethod>(methodIndex);
    options.useRandomization = ConfigManager::GetInstance().GetUseRandomization();
    options.cleanupPEHeaders = ConfigManager::GetInstance().GetCleanupPEHeaders();
    options.useEvasionTechniques = ConfigManager::GetInstance().GetUseEvasionTechniques();
    options.waitForExit = ConfigManager::GetInstance().GetWaitForExit();
    options.timeout = ConfigManager::GetInstance().GetTimeout();
    
    // Perform injection
    CS2Injector::Injector injector;
    CS2Injector::InjectionError result = injector.Initialize(options, 
        [this](const std::wstring& message) {
            // Log callback
            this->AddStatusMessage(message);
        });
    
    if (result != CS2Injector::InjectionError::SUCCESS) {
        // Enable controls
        EnableWindow(hInjectButton_, TRUE);
        EnableWindow(hRefreshButton_, TRUE);
        
        // Show error
        std::wstring errorMessage = L"Failed to initialize injector: " + injector.GetLastErrorMessage();
        SetStatusText(errorMessage);
        ShowError(errorMessage);
        return false;
    }
    
    // Set injection callback
    injector.SetCallback([this](CS2Injector::InjectionError error, const std::wstring& message) {
        // Injection callback
        this->HandleInjectionResult(error);
    });
    
    // Perform the injection
    result = injector.Inject();
    
    // Handle result
    HandleInjectionResult(result);
    
    // Enable controls
    EnableWindow(hInjectButton_, TRUE);
    EnableWindow(hRefreshButton_, TRUE);
    
    return (result == CS2Injector::InjectionError::SUCCESS);
}

// Helper to handle injection result
void UIManager::HandleInjectionResult(CS2Injector::InjectionError result) {
    if (result == CS2Injector::InjectionError::SUCCESS) {
        SetStatusText(L"Injection successful!");
        
        // Auto-close if in silent mode
        if (ConfigManager::GetInstance().GetSilentMode()) {
            Sleep(ConfigManager::GetInstance().GetCloseDelay());
            Exit();
        }
    } else {
        std::wstring errorMessage = L"Injection failed: " + CS2Injector::GetErrorString(result);
        SetStatusText(errorMessage);
        ShowError(errorMessage);
    }
}

// Add a status message
void UIManager::AddStatusMessage(const std::wstring& message) {
    // Update status text
    SetStatusText(message);
    
    // Call status callback if set
    if (statusCallback_) {
        statusCallback_(message);
    }
}

// Set status callback
void UIManager::SetStatusCallback(StatusCallback callback) {
    statusCallback_ = callback;
}

// Handle command (to be implemented)
void UIManager::HandleCommand(WORD command) {
    switch (command) {
    case IDC_INJECT_BUTTON:
        InjectDLL();
        break;
        
    case IDC_BROWSE_BUTTON:
        SelectDLLFile();
        break;
        
    case IDC_REFRESH_BUTTON:
        UpdateProcessList();
        break;
        
    case IDC_SETTINGS_BUTTON:
        ShowSettingsDialog();
        break;
        
    case IDC_ABOUT_BUTTON:
        ShowAboutDialog();
        break;
        
    case IDC_EXIT_BUTTON:
        Exit();
        break;
    }
}

// Handle notify messages
void UIManager::HandleNotify(LPARAM lParam) {
    NMHDR* pnmh = (NMHDR*)lParam;
    
    // Handle control notifications
    switch (pnmh->code) {
    case CBN_SELCHANGE:
        if (pnmh->idFrom == IDC_PROCESS_COMBO) {
            // Process selection changed
            int index = static_cast<int>(SendMessage(hProcessCombo_, CB_GETCURSEL, 0, 0));
            if (index != CB_ERR) {
                wchar_t processName[MAX_PATH];
                SendMessage(hProcessCombo_, CB_GETLBTEXT, index, (LPARAM)processName);
                ConfigManager::GetInstance().SetProcessName(processName);
                ConfigManager::GetInstance().SaveConfig();
            }
        }
        else if (pnmh->idFrom == IDC_METHOD_COMBO) {
            // Injection method changed
            int index = static_cast<int>(SendMessage(hMethodCombo_, CB_GETCURSEL, 0, 0));
            if (index != CB_ERR) {
                ConfigManager::GetInstance().SetInjectionMethod(static_cast<CS2Injector::InjectionMethod>(index));
                ConfigManager::GetInstance().SaveConfig();
            }
        }
        break;
    }
}

// Handle tray icon (to be implemented)
void UIManager::HandleTrayIcon(LPARAM lParam) {
    switch (LOWORD(lParam)) {
    case WM_LBUTTONUP:
        RestoreFromTray();
        break;
        
    case WM_RBUTTONUP:
        {
            // Create tray menu if it doesn't exist
            if (!hTrayMenu_) {
                hTrayMenu_ = CreatePopupMenu();
                AppendMenuW(hTrayMenu_, MF_STRING, IDC_INJECT_BUTTON, L"Inject");
                AppendMenuW(hTrayMenu_, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hTrayMenu_, MF_STRING, IDC_REFRESH_BUTTON, L"Refresh");
                AppendMenuW(hTrayMenu_, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hTrayMenu_, MF_STRING, IDC_SETTINGS_BUTTON, L"Settings");
                AppendMenuW(hTrayMenu_, MF_STRING, IDC_ABOUT_BUTTON, L"About");
                AppendMenuW(hTrayMenu_, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hTrayMenu_, MF_STRING, 1, L"Restore");
                AppendMenuW(hTrayMenu_, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hTrayMenu_, MF_STRING, IDC_EXIT_BUTTON, L"Exit");
            }
            
            // Get cursor position
            POINT pt;
            GetCursorPos(&pt);
            
            // Show tray menu
            SetForegroundWindow(hWnd_);
            UINT cmd = TrackPopupMenu(hTrayMenu_, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hWnd_, NULL);
            PostMessage(hWnd_, WM_NULL, 0, 0);
            
            // Handle menu command
            switch (cmd) {
            case 1: // Restore
                RestoreFromTray();
                break;
                
            case IDC_INJECT_BUTTON:
                InjectDLL();
                break;
                
            case IDC_REFRESH_BUTTON:
                UpdateProcessList();
                break;
                
            case IDC_SETTINGS_BUTTON:
                ShowSettingsDialog();
                break;
                
            case IDC_ABOUT_BUTTON:
                ShowAboutDialog();
                break;
                
            case IDC_EXIT_BUTTON:
                Exit();
                break;
            }
        }
        break;
    }
}

// Set status text
void UIManager::SetStatusText(const std::wstring& status) {
    statusText_ = status;
    if (hStatusText_) {
        SetWindowTextW(hStatusText_, status.c_str());
    }
}

// Select DLL file via dialog
void UIManager::SelectDLLFile() {
    wchar_t fileName[MAX_PATH] = { 0 };
    
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hWnd_;
    ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt = L"dll";
    
    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(hDllPathEdit_, fileName);
        ConfigManager::GetInstance().SetDllPath(fileName);
        ConfigManager::GetInstance().SaveConfig();
    }
}

// Show error message
void UIManager::ShowError(const std::wstring& message) {
    MessageBoxW(hWnd_, message.c_str(), L"Error", MB_ICONERROR | MB_OK);
}

// Show information message
void UIManager::ShowInfo(const std::wstring& message) {
    MessageBoxW(hWnd_, message.c_str(), L"Information", MB_ICONINFORMATION | MB_OK);
}

// Show confirmation dialog
bool UIManager::ShowConfirmation(const std::wstring& message) {
    return MessageBoxW(hWnd_, message.c_str(), L"Confirmation", MB_ICONQUESTION | MB_YESNO) == IDYES;
}

// Restore from tray
void UIManager::RestoreFromTray() {
    // Show and activate the window
    ShowWindow(hWnd_, SW_SHOW);
    SetForegroundWindow(hWnd_);
    isMinimized_ = false;
}

// Show settings dialog
void UIManager::ShowSettingsDialog() {
    // In a real implementation, this would show a dialog
    // For simplicity, we'll just toggle some settings
    
    bool useRandomization = ConfigManager::GetInstance().GetUseRandomization();
    bool cleanupPEHeaders = ConfigManager::GetInstance().GetCleanupPEHeaders();
    bool useEvasionTechniques = ConfigManager::GetInstance().GetUseEvasionTechniques();
    
    // Toggle settings
    ConfigManager::GetInstance().SetUseRandomization(!useRandomization);
    ConfigManager::GetInstance().SetCleanupPEHeaders(!cleanupPEHeaders);
    ConfigManager::GetInstance().SetUseEvasionTechniques(!useEvasionTechniques);
    
    // Save settings
    ConfigManager::GetInstance().SaveConfig();
    
    // Show confirmation
    std::wstring message = L"Settings updated:\n";
    message += L"Use Randomization: " + std::wstring(ConfigManager::GetInstance().GetUseRandomization() ? L"Yes" : L"No") + L"\n";
    message += L"Cleanup PE Headers: " + std::wstring(ConfigManager::GetInstance().GetCleanupPEHeaders() ? L"Yes" : L"No") + L"\n";
    message += L"Use Evasion Techniques: " + std::wstring(ConfigManager::GetInstance().GetUseEvasionTechniques() ? L"Yes" : L"No");
    
    ShowInfo(message);
}

// Show about dialog
void UIManager::ShowAboutDialog() {
    std::wstring message = L"CS2 Injector v1.0.0\n\n";
    message += L"An educational tool for understanding Windows memory manipulation.\n\n";
    message += L"Warning: This is for educational purposes only. Use on games like CS2 may violate\n";
    message += L"the terms of service and result in a ban. Use at your own risk.\n\n";
    message += L"© 2023-2024 CS2Injector Contributors\n";
    message += L"Released under MIT License";
    
    ShowInfo(message);
}

// Set process name
void UIManager::SetProcessName(const std::wstring& processName) {
    ConfigManager::GetInstance().SetProcessName(processName);
    
    // Update combo box selection
    int count = static_cast<int>(SendMessage(hProcessCombo_, CB_GETCOUNT, 0, 0));
    for (int i = 0; i < count; i++) {
        wchar_t name[MAX_PATH];
        SendMessage(hProcessCombo_, CB_GETLBTEXT, i, (LPARAM)name);
        
        if (_wcsicmp(name, processName.c_str()) == 0) {
            SendMessage(hProcessCombo_, CB_SETCURSEL, i, 0);
            break;
        }
    }
}

// Get process name
std::wstring UIManager::GetProcessName() const {
    int index = static_cast<int>(SendMessage(hProcessCombo_, CB_GETCURSEL, 0, 0));
    if (index == CB_ERR) {
        return L"";
    }
    
    wchar_t name[MAX_PATH];
    SendMessage(hProcessCombo_, CB_GETLBTEXT, index, (LPARAM)name);
    
    return name;
}

// Set DLL path
void UIManager::SetDllPath(const std::wstring& dllPath) {
    ConfigManager::GetInstance().SetDllPath(dllPath);
    SetWindowText(hDllPathEdit_, dllPath.c_str());
}

// Get DLL path
std::wstring UIManager::GetDllPath() const {
    wchar_t path[MAX_PATH];
    GetWindowText(hDllPathEdit_, path, MAX_PATH);
    
    return path;
}

// Set injection method
void UIManager::SetInjectionMethod(CS2Injector::InjectionMethod method) {
    ConfigManager::GetInstance().SetInjectionMethod(method);
    
    // Update combo box selection
    SendMessage(hMethodCombo_, CB_SETCURSEL, static_cast<WPARAM>(method), 0);
}

// Get injection method
CS2Injector::InjectionMethod UIManager::GetInjectionMethod() const {
    int index = static_cast<int>(SendMessage(hMethodCombo_, CB_GETCURSEL, 0, 0));
    if (index == CB_ERR) {
        return CS2Injector::InjectionMethod::MANUAL_MAP; // Default
    }
    
    return static_cast<CS2Injector::InjectionMethod>(index);
}

// Check if process is running
bool UIManager::IsProcessRunning() const {
    std::wstring processName = GetProcessName();
    if (processName.empty()) {
        return false;
    }
    
    return Injector::IsProcessRunning(processName);
}

// Set window title
void UIManager::SetWindowTitle(const std::wstring& title) {
    SetWindowText(hWnd_, title.c_str());
}

// Apply settings from config
void UIManager::ApplySettings() {
    // Set DLL path
    SetDllPath(ConfigManager::GetInstance().GetDllPath());
    
    // Set injection method
    SetInjectionMethod(ConfigManager::GetInstance().GetInjectionMethod());
    
    // Apply window style
    ApplyWindowStyle();
    
    // Hide console if needed
    if (ConfigManager::GetInstance().GetHideConsole()) {
        ShowWindow(GetConsoleWindow(), SW_HIDE);
    }
}

// Create brushes for custom drawing
void UIManager::CreateBrushes() {
    // Create brushes
    hBackgroundBrush_ = CreateSolidBrush(backgroundColor_);
    hButtonBrush_ = CreateSolidBrush(accentColor_);
    hEditBrush_ = CreateSolidBrush(RGB(50, 50, 50));
    hComboBoxBrush_ = CreateSolidBrush(RGB(50, 50, 50));
} 