### WORK IN PROGRESS

# CS2 Injector

A sophisticated 64-bit DLL injector for Counter-Strike 2, inspired by Shtreeba but designed for modern games and anti-cheat systems.

## Features

* **Advanced Injection Methods**
  * LoadLibrary - Traditional DLL loading
  * Manual Mapping - Stealthy PE mapping with proper relocations and imports
  * Thread Hijacking - Execution via existing threads
  * Shellcode Injection - Custom shellcode execution

* **Anti-Detection Techniques**
  * Memory Cloaking - Hide memory regions from scanning
  * PE Header Cleanup - Remove evidence of injection
  * Import Obfuscation - Hide suspicious imports
  * Call Stack Spoofing - Hide suspicious call stacks
  * Thread Context Manipulation - Stealthy execution
  * Timing Manipulation - Bypass timing-based detection
  
* **Memory Management**
  * Randomized Memory Allocation - Non-predictable memory addresses
  * Memory Protection Manipulation - Secure regions from scanning
  * Pattern Scanning - Find specific signatures in memory
  
* **Process Handling**
  * Process List Management - Find target processes
  * Module Management - Handle DLL modules
  * Thread Management - Manipulate process threads
  
* **User Interface**
  * Modern UI - Clean, intuitive design
  * Process Selection - Easy target selection
  * Injection Method Configuration - Choose your technique
  * Status Monitoring - Track injection progress
  * Theme Support - Customizable appearance
  * Tray Integration - Minimize to system tray

## Building CS2 Injector

### Prerequisites

1. **Windows 10 or 11** (64-bit)
2. **Visual Studio 2019 or newer** with the following components:
   - C++ Desktop Development workload
   - Windows 10/11 SDK
   - MSVC v142 or newer build tools

### Build Steps

1. **Open the solution file**
   - Double-click on `CS2Injector.sln` to open it in Visual Studio

2. **Select build configuration**
   - Set to `Release | x64` in the Visual Studio toolbar

3. **Build the solution**
   - Press `Ctrl+Shift+B` or select Build → Build Solution from the menu
   - Alternatively, right-click on the solution in Solution Explorer and select "Build Solution"

4. **Find the built files**
   - After a successful build, the binaries will be in the `bin\Release` folder
   - The UI application is `CS2Injector.exe`
   - The injection library is `CS2Injector.dll`

### Running the Injector

1. Run `CS2Injector.exe` **as administrator** (right-click → Run as administrator)
2. Select the target process (CS2)
3. Select or browse for the DLL to inject
4. Choose your preferred injection method (Manual Map is recommended)
5. Click "Inject"

### Command Line Options

The injector supports the following command line options:

- `-inject`: Automatically inject the DLL at startup
- `-process <name>`: Specify the target process name
- `-dll <path>`: Specify the DLL path
- `-method <number>`: Specify the injection method (0: LoadLibrary, 1: Manual Map, 2: Thread Hijacking, 3: Shellcode)
- `-silent`: Enable silent mode (automatically close after injection)
- `-minimize`: Start minimized to tray
- `-exit`: Exit after injection

Example: `CS2Injector.exe -process cs2.exe -dll myhack.dll -method 1 -inject`

### Troubleshooting

- **Missing DLL errors**: Ensure you have the Microsoft Visual C++ Redistributable for Visual Studio 2019/2022 installed
- **Access denied errors**: Run as administrator
- **Injection fails**: Try a different injection method or check if the target process is protected
- **UI does not appear**: Check if the application is minimized to the system tray

### Warning

This tool is provided for educational purposes only. Using it to modify online games may violate terms of service agreements and result in account bans. Use at your own risk and only on private, offline servers that you own or have permission to modify.

## Getting Started

### Prerequisites

* Windows 10/11 (64-bit)
* Microsoft Visual Studio 2019 or newer
* Administrator privileges (required for injection)

### Building from Source

1. Clone the repository
2. Open `CS2Injector.sln` in Visual Studio
3. Set build configuration to `Release | x64`
4. Build the solution
5. Find the built executables in the `bin\Release` folder

### Usage

1. Run `CS2Injector.exe` with administrator privileges
2. Select CS2 from the process list (or enter "cs2.exe" manually)
3. Choose your DLL to inject
4. Select injection method (Manual Mapping recommended for stealth)
5. Configure additional options if needed
6. Click "Inject"

### Configuration

The application creates a `CS2Injector.ini` file with the following settings:

```ini
[Library]
DLL=payload.dll
ProcessName=cs2.exe
InjectionMethod=1
UseRandomization=1
CleanupPEHeaders=1
UseEvasionTechniques=1
WaitForExit=0
Timeout=10000

[UI]
Silent=0
CloseDelay=3000
Theme=Dark
MinimizeToTray=0
StartWithWindows=0
HideConsole=1
AutoInject=0
```

## Command Line Options

The injector supports the following command line options:

```
CS2Injector.exe -inject -process [process name] -dll [dll path] -method [method number] -silent -minimize -exit
```

* `-inject`: Automatically inject on startup
* `-process`: Specify the target process name
* `-dll`: Specify the DLL path to inject
* `-method`: Specify the injection method (0=LoadLibrary, 1=ManualMap, 2=ThreadHijack, 3=Shellcode)
* `-silent`: Enable silent mode (no messages)
* `-minimize`: Start minimized
* `-exit`: Exit after injection

## Technical Details

### Injection Methods

1. **LoadLibrary**  
   Uses the standard LoadLibrary API to load DLLs. Simplest but least stealthy method.

2. **Manual Mapping**  
   Manually maps the DLL into the target process by:
   - Parsing PE headers
   - Allocating memory
   - Mapping sections
   - Resolving imports
   - Handling relocations
   - Executing TLS callbacks
   - Calling DllMain

3. **Thread Hijacking**  
   Executes code by:
   - Finding a suitable thread
   - Suspending it
   - Saving its context
   - Modifying the instruction pointer
   - Resuming the thread
   - Restoring the original context after execution

4. **Shellcode Injection**  
   Executes custom shellcode that:
   - Contains position-independent code
   - Can load and execute the DLL
   - Obfuscated to avoid detection

### Anti-Detection Techniques

* **Memory Cloaking**: Creates decoy memory regions and hides real ones.
* **PE Header Cleanup**: Removes PE headers after mapping to prevent scanning.
* **Import Obfuscation**: Resolves imports dynamically to hide suspicious function calls.
* **Call Stack Cleaning**: Manipulates the call stack to remove evidence of injection.
* **Timing Manipulation**: Adds randomized delays to avoid timing-based detection.

## Educational Purpose

This project is designed for educational purposes to understand:
- Windows process manipulation
- DLL injection techniques
- Memory management
- Anti-cheat evasion methods
- PE file format parsing
- Thread manipulation
- GUI application development

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

* Inspired by the Shtreeba injector
* Built for modern 64-bit Counter-Strike 2

## Disclaimer

This software is provided for educational purposes only. Usage of this injector for cheating in online games may violate the terms of service and could result in account bans. The authors do not condone cheating and are not responsible for misuse of this software. 
