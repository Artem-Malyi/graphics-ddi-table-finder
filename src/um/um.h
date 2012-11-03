#pragma once

// Comment the following symbol in order to switch off debug output.
#define DEBUG_OUTPUT_UM



// These values may be overridden from command line:
#define DEFAULT_DCOBJ_ITERATIONS 100
#define DEFAULT_PDEV_ITERATIONS 1000

#define OUTPUT_BUFFER_SIZE 512

#ifdef DEBUG_OUTPUT_UM
    #define LOG_OUTPUT_UM(fmt, ...)                                                         \
    {                                                                                       \
        WCHAR wsOutput[OUTPUT_BUFFER_SIZE] = {0};                                           \
        _snwprintf(wsOutput, OUTPUT_BUFFER_SIZE, L"OFFSET-FINDER UM: %S - "##fmt##L"\r\n",  \
            __FUNCTION__, __VA_ARGS__);                                                     \
        OutputDebugString(wsOutput);                                                        \
    }
#else 
    #define LOG_OUTPUT_UM(...)
#endif


#define print(fmt, ...)                                                                             \
{                                                                                                   \
    static WCHAR wsOutput[OUTPUT_BUFFER_SIZE] = {0};                                                \
    _snwprintf(wsOutput, OUTPUT_BUFFER_SIZE, fmt, __VA_ARGS__);                                     \
    DWORD dwWritten = 0;                                                                            \
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), wsOutput, wcslen(wsOutput), &dwWritten, NULL);    \
}


// DbgHelp functions
typedef BOOL (WINAPI *SymInitialize_t)(
    __in HANDLE   hProcess,
    __in PSTR     UserSearchPath,
    __in BOOL     fInvadeProcess
    );

typedef struct {
    DWORD sizeofstruct;
    TCHAR file[MAX_PATH +1];
    BOOL  stripped;
    DWORD timestamp;
    DWORD size;
    TCHAR dbgfile[MAX_PATH +1];
    TCHAR pdbfile[MAX_PATH + 1];
    GUID  guid;
    DWORD sig;
    DWORD age;
} SYMSRV_INDEX_INFO, *PSYMSRV_INDEX_INFO;

typedef BOOL (WINAPI *SymSrvGetFileIndexInfo_t)(
    __in   PWSTR File,
    __out  PSYMSRV_INDEX_INFO Info,
    __in   DWORD Flags
    );

typedef BOOL (WINAPI *SymFindFileInPath_t)(
    __in      HANDLE hProcess,
    __in_opt  PCSTR SearchPath,
    __in      PCSTR FileName,
    __in_opt  PVOID id,
    __in      DWORD two,
    __in      DWORD three,
    __in      DWORD flags,
    __out     PSTR FilePath,
    __in_opt  PFINDFILEINPATHCALLBACK callback,
    __in_opt  PVOID context
    );

typedef DWORD64 (WINAPI *SymLoadModuleEx_t)(
    __in  HANDLE         hProcess,
    __in  HANDLE         hFile,
    __in  PSTR           ImageName,
    __in  PSTR           ModuleName,
    __in  DWORD64        BaseOfDll,
    __in  DWORD          DllSize,
    __in  PMODLOAD_DATA  Data,
    __in  DWORD          Flags
    );

typedef BOOL (WINAPI *SymGetModuleInfo64_t)(
    __in  HANDLE                  hProcess,
    __in  DWORD64                 qwAddr,
    __out PIMAGEHLP_MODULE64      ModuleInfo
    );

typedef BOOL (WINAPI *SymGetSymFromName64_t)(
    __in  HANDLE              hProcess,
    __in  PSTR                Name,
    __out PIMAGEHLP_SYMBOL64  Symbol
    );

typedef BOOL (WINAPI *SymCleanup_t)(
    __in HANDLE hProcess
    );

typedef DWORD (WINAPI *SymSetOptions_t)(
    __in DWORD   SymOptions
    );

typedef DWORD (WINAPI *SymGetOptions_t)(
    VOID
    );


class CSymbolsHandle
{
public:
    CSymbolsHandle(HANDLE handle): m_handle(handle) 
    {
        HMODULE hDbgHelp = GetModuleHandle(L"dbghelp.dll");
        if (!hDbgHelp)
            hDbgHelp = LoadLibrary(L"dbghelp.dll");
        
        m_pSymCleanup = (SymCleanup_t)GetProcAddress(hDbgHelp, "SymCleanup");
    }

    ~CSymbolsHandle()
    { 
        if (m_pSymCleanup)
            m_pSymCleanup(m_handle); 
    }

    operator HANDLE(){ return m_handle; }

private:
    HANDLE m_handle;
    SymCleanup_t m_pSymCleanup;
};


typedef BOOL (WINAPI *Wow64DisableWow64FsRedirection_t)(
    __out  PVOID *OldValue
    );

typedef BOOL (WINAPI *Wow64RevertWow64FsRedirection_t)(
    __in  PVOID OldValue
    );

typedef BOOL (WINAPI *IsWow64Process_t)(
    __in   HANDLE hProcess,
    __out  PBOOL Wow64Process
    );

class CWow64FsRedirHandler
{
public:
    CWow64FsRedirHandler()
    {
        m_OldRedirValue = NULL;
        m_bIs64Bit = FALSE;

        m_pIsWow64Process = (IsWow64Process_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "IsWow64Process");
        m_pWow64DisableWow64FsRedirection = (Wow64DisableWow64FsRedirection_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Wow64DisableWow64FsRedirection");
        m_pWow64RevertWow64FsRedirection = (Wow64RevertWow64FsRedirection_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Wow64RevertWow64FsRedirection");
        
        if (m_pIsWow64Process)
        {
            BOOL bIsWow64 = FALSE;    
            m_pIsWow64Process(GetCurrentProcess(), &bIsWow64);
            if (bIsWow64)
                m_bIs64Bit = TRUE;
        }

        if (m_bIs64Bit && m_pWow64DisableWow64FsRedirection)
            m_pWow64DisableWow64FsRedirection(&m_OldRedirValue);
    }

    ~CWow64FsRedirHandler()
    {
        if (m_bIs64Bit && m_pWow64RevertWow64FsRedirection)
            m_pWow64DisableWow64FsRedirection(&m_OldRedirValue);
    }

    BOOL Is64BitOS() { return m_bIs64Bit; }

private:
    BOOL                                m_bIs64Bit;
    PVOID                               m_OldRedirValue;
    IsWow64Process_t                    m_pIsWow64Process;
    Wow64DisableWow64FsRedirection_t    m_pWow64DisableWow64FsRedirection;
    Wow64RevertWow64FsRedirection_t     m_pWow64RevertWow64FsRedirection;
};

class CAutoHDC
{
public:
    enum FreeMethodEnum_t
    {
        FM_DELETE,
        FM_RELEASE
    };

    explicit CAutoHDC(HDC hdc, FreeMethodEnum_t free_method, HWND hWnd = NULL)
        :m_hDC(hdc)
        ,m_freeMethod(free_method)
        ,m_hWnd(hWnd)
    {
    }

    ~CAutoHDC()
    {
        if ( NULL != m_hDC )
        {
            switch(m_freeMethod)
            {
            case FM_RELEASE:
                ::ReleaseDC( m_hWnd,m_hDC);
                break;
            case FM_DELETE:
                ::DeleteDC(m_hDC);
                break;
            default:
                // TODO: Add warning here
                ;                  
            }            
        }
    }
    HDC Get() const
    {
        return m_hDC;
    }    
private:
    CAutoHDC(const CAutoHDC&);
    CAutoHDC& operator=(const CAutoHDC&);
    HDC                 m_hDC;
    HWND                m_hWnd;
    FreeMethodEnum_t    m_freeMethod;
};


typedef struct _GdiHandle {
    unsigned long Index         :12;
    unsigned long Reserved      :4;
    unsigned long ObjectType    :7;
    unsigned long StdObject     :1;
    unsigned long Unknown       :8;
} GdiHandle, *PGdiHandle;


typedef struct _GdiTableEntry32 {
    __int32         pKernel;
    unsigned short  nProcess;
    unsigned short  nCount;
    unsigned short  nUpper;
    unsigned short  nType;
    __int32         pUser;
} GdiTableEntry32, *PGdiTableEntry32;

typedef struct _GdiTableEntry64 {
    __int64         pKernel;
    unsigned short  nProcess;
    unsigned short  nCount;
    unsigned short  nUpper;
    unsigned short  nType;
    __int64         pUser;
} GdiTableEntry64, *PGdiTableEntry64;

typedef struct _InstDriverContext {
    WCHAR wsFsPathToDriver[MAX_PATH];
    WCHAR wsRegPathToService[MAX_PATH];
    WCHAR wsRegPathToServiceNative[MAX_PATH];
    BOOL bInstalled;
} InstDriverContext, *PInstDriverContext;


typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

extern "C"
{
    NTSYSAPI VOID NTAPI RtlInitUnicodeString(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
        );

    NTSYSAPI NTSTATUS NTAPI ZwLoadDriver(
        PUNICODE_STRING RegistryPath
        );

    NTSYSAPI NTSTATUS NTAPI ZwUnloadDriver(
        PUNICODE_STRING RegistryPath
        );
};
