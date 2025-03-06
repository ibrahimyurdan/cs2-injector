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