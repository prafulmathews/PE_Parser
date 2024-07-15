A Portable Executable (PE) parser written in C.  
Parses the Dos header, File header, Optional header and Section headers.  
Looks up the Import Address Table (IAT) and lists the functions imported from their corresponding DLL files.  

To use, compile the binary and run in a terminal while supplying the name of the PE file you want to parse.
```
PS E:\Projects\C_PEParser\PEparser\x64\Release> .\PEparser.exe .\spoofingprocarg.exe
.\spoofingprocarg.exe   File Size: 13824        File Present At: 0x0000022B73AA3FF0

####### DOS HEADER #######
Magic Number: 0x5A4D
Relative File Address of EXE Header: 0x00000100

####### NT_SIGNATURE #######
Signature: 0x4550

####### FILE_HEADER #######
Architectue: x64
FileType: EXE
Number of Sections: 6
Size of Optional Header: 240

####### OPTIONAL HEADER #######
Magic (Architecture): x64 (0x20B)

RVA of Entry Point: 0x000018A0
Actual Address of Entry Point : 0x0000022B73AA5890

Size of code section: 5120
RVA of code section: 0x00001000
Actual Address of Code Section: 0000022B73AA4FF0

Size of Initialized Data: 9216
Size of Uninitialized Data: 0
Size Of Image: 36864

Required Version: 6:0
File Checksum: 0x00000000
Preferred Mapping Address: 0x0000000140000000
Number of Enteries in the DataDirectory: 16

####### DATA DIRECTORIES #######
Export Directory: 0x0000022B73AA3FF0
                Size: 0         RVA: 0x00000000

Import Directory: 0x0000022B73AA7D1C
                Size: 160               RVA: 0x00003D2C

Resource Directory: 0x0000022B73AAAFF0
                Size: 480               RVA: 0x00007000

Exception Directory: 0x0000022B73AA9FF0
                Size: 432               RVA: 0x00006000

Security Directory: 0x0000022B73AA3FF0
                Size: 0         RVA: 0x00000000

Base Relocation Directory: 0x0000022B73AABFF0
                Size: 48                RVA: 0x00008000

Debug Directory: 0x0000022B73AA7790
                Size: 112               RVA: 0x000037A0

TLS Directory: 0x0000022B73AA3FF0
                Size: 0         RVA: 0x00000000

IAT Directory: 0x0000022B73AA6FF0
                Size: 512               RVA: 0x00003000

####### SECTION HEADERS #######
Name: .text
        Size: 5120
        RVA: 0x00001000
        Address: 0x0000022B73AA4FF0
        Number of Relocations: 0        Permissions: PAGE_EXECUTE_READWRITE
Name: .rdata
        Size: 5632
        RVA: 0x00003000
        Address: 0x0000022B73AA6FF0
        Number of Relocations: 0        Permissions: PAGE_READ
Name: .data
        Size: 512
        RVA: 0x00005000
        Address: 0x0000022B73AA8FF0
        Number of Relocations: 0        Permissions: PAGE_READWRITE
Name: .pdata
        Size: 512
        RVA: 0x00006000
        Address: 0x0000022B73AA9FF0
        Number of Relocations: 0        Permissions: PAGE_READ
Name: .rsrc
        Size: 512
        RVA: 0x00007000
        Address: 0x0000022B73AAAFF0
        Number of Relocations: 0        Permissions: PAGE_READ
Name: .reloc
        Size: 512
        RVA: 0x00008000
        Address: 0x0000022B73AABFF0
        Number of Relocations: 0        Permissions: PAGE_READ


####### IMPORT ADDRESS TABLE #######
Imported DLL: KERNEL32.dll
        WriteProcessMemory
        HeapFree
        lstrlenW
        ResumeThread
        GetLastError
        HeapAlloc
        GetProcAddress
        ReadProcessMemory
        GetProcessHeap
        CreateProcessW
        GetModuleHandleW
        lstrcpyW
        RtlLookupFunctionEntry
        RtlVirtualUnwind
        UnhandledExceptionFilter
        SetUnhandledExceptionFilter
        RtlCaptureContext
        GetCurrentProcess
        IsDebuggerPresent
        InitializeSListHead
        GetSystemTimeAsFileTime
        GetCurrentThreadId
        GetCurrentProcessId
        QueryPerformanceCounter
        IsProcessorFeaturePresent
        TerminateProcess

Imported DLL: VCRUNTIME140.dll
        __C_specific_handler
        __current_exception
        __current_exception_context
        memset
        memcpy

Imported DLL: api-ms-win-crt-stdio-l1-1-0.dll
        __stdio_common_vfprintf
        __stdio_common_vfwprintf
        __acrt_iob_func
        __p__commode
        _set_fmode

Imported DLL: api-ms-win-crt-runtime-l1-1-0.dll
        _initialize_onexit_table
        _register_onexit_function
        _c_exit
        _crt_atexit
        terminate
        _seh_filter_exe
        _set_app_type
        _register_thread_local_exe_atexit_callback
        __p___argc
        _cexit
        _exit
        exit
        _initterm_e
        _initterm
        _get_initial_narrow_environment
        _initialize_narrow_environment
        _configure_narrow_argv
        __p___argv

Imported DLL: api-ms-win-crt-math-l1-1-0.dll
        __setusermatherr

Imported DLL: api-ms-win-crt-locale-l1-1-0.dll
        _configthreadlocale

Imported DLL: api-ms-win-crt-heap-l1-1-0.dll
        _set_new_mode
