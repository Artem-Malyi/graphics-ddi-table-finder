#define WIN32_LEAN_AND_MEAN 

#pragma warning(disable:4996)

#include <windows.h>
#include <string>
#include <dbghelp.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <winioctl.h>

#include "resource.h"
#include "um.h"
#include "common.h"

InstDriverContext   g_drvCtx = {0};

DWORD64     GetSymbolAddress        (PWSTR wsImageFilePath, PWSTR wsSymbolName);
BOOL        FillDDIpointers         (PDDI_PFNS pDdiPointers);
BOOL        GetKernelDcObjPointer   (PLARGE_INTEGER pliGdiTablePointer);
BOOL        ExtractRedistDllToCurDir        (PWSTR wsDllName, ULONG ulResourceId);
BOOL        InstallDriver           (PInstDriverContext pDrvCtx);
BOOL        UninstallDriver         (PInstDriverContext pDrvCtx);
BOOL        ObtainCommandLineArgs   (ULONG& ulDCOBJiterations, ULONG& ulPDEViterations);

BOOL        ShowProcessPrivileges   ();
BOOL        SetPrivilege            (PWSTR lpszPrivilege, BOOL bEnablePrivilege); 


LONG __stdcall TopLevelExceptionHandler(PEXCEPTION_POINTERS pInfo) 
{
    LOG_OUTPUT_UM(L"SEH exception occurred");

    if (g_drvCtx.bInstalled)
        UninstallDriver(&g_drvCtx);

    ExitProcess (-1);
    return 0;
}

typedef BOOL (WINAPI *SetDllDirectoryW_t)(PWSTR wsPathName);

void main()
{
    SetUnhandledExceptionFilter(TopLevelExceptionHandler);

    print(L"\n\tDDI Table Offset Finder 0.1\n");
    print(L"Usage: offset-finder.exe <DCOBJ-iterations> <PDEV-iterations>\n");

    // obtain command line parameters
    ULONG ulDCOBJiterations = 0, ulPDEViterations = 0;
    BOOL bRet = ObtainCommandLineArgs(ulDCOBJiterations, ulPDEViterations);
    if (!bRet)
    {
        print(L"Incorrect command line. See Usage section above.\n");
        ExitProcess (-1);
    }

    // extract redistributable dlls symsrv.dll, symsrv.yes and dbghelp.dll to current directory
    if (!ExtractRedistDllToCurDir(L"dbghelp.dll", DBGHELPDLL) ||
        !ExtractRedistDllToCurDir(L"symsrv.dll", SYMSRVDLL))
    {
        print(L"Could not extract needed redistributable dlls.\n");
        ExitProcess (-1);
    }
   
    print(L"Try to obtain symbols information for WIN32K.SYS. This may take some time\n");
    
    DDI_PFNS ddiPfns = {0};
    bRet = FillDDIpointers(&ddiPfns);
    if (!bRet)
    {
        print(L"Failed obtain symbols info and fill DDI pointers table. Status: %d\n", GetLastError());
        ExitProcess (-1);
    }

    print(L"Try to obtain symbols information for GDI32.DLL. This may take some time\n");
    LARGE_INTEGER liKernelDcObjPointer = {0};
    bRet = GetKernelDcObjPointer(&liKernelDcObjPointer);
    if (!bRet)
    {
        print(L"Failed obtain symbols info for GDI32.dll. Status: %d\n", GetLastError());
        ExitProcess (-1);
    }
   
    print(L"Try to install kernel mode component\n");
    bRet = InstallDriver(&g_drvCtx);
    if (!bRet)
    {
        print(L"Failed to install driver. Status: %d. Is driver signature enforcement disabled?\n", GetLastError());
        ExitProcess (-1);
    }

    HANDLE hDevice = CreateFile(L"\\\\.\\" DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hDevice)
    {
        print(L"Failed to contact kernel mode component. Status: %d\n", GetLastError());
        UninstallDriver(&g_drvCtx);
        ExitProcess (-1);
    }

    // Pass all the needed info to the kernel mode component
    DDI_OFFSET_FINDER_INFO ofInfo = {0};
    ofInfo.ulDCOBJiterations = ulDCOBJiterations;
    ofInfo.ulPDEViterations = ulPDEViterations;
    ofInfo.pKernelDcObj.QuadPart = liKernelDcObjPointer.QuadPart;
    memcpy(&ofInfo.ddiPfns, &ddiPfns, sizeof(ofInfo.ddiPfns));
    print(L"Going to perform kernel memory scan from 0x%llx location\n", ofInfo.pKernelDcObj.QuadPart);
    print(L"    with the following iteration values: DCOBJ - %d, PDEV_WIN32K - %d\n", ofInfo.ulDCOBJiterations, ofInfo.ulPDEViterations);
    Sleep(100);

    DWORD dwReturned = 0;
    DDI_FOUND_OFFSETS foundOffs = {0};
    BOOL bResult = DeviceIoControl(hDevice, IOCTL_PASS_INFO, &ofInfo, sizeof(ofInfo), &foundOffs, sizeof(foundOffs), &dwReturned, NULL);
    if (!hDevice || !bResult)
    {
        print(L"Failed to start the scan. Status: %d\n", GetLastError());
        UninstallDriver(&g_drvCtx);
        ExitProcess (-1);
    }
    // TODO: Wait for the result with some progress indicator
    LOG_OUTPUT_UM(L"Bytes returned: %d, bResult: %d", dwReturned, bResult);
    LOG_OUTPUT_UM(L"Offset values: DCOBJ - 0x%04x, PDEV_WIN32K - 0x%04x", foundOffs.ulDCOBJoffset, foundOffs.ulPDEVoffset);

    if (foundOffs.ulDCOBJoffset == NOT_FOUND_OFFSET ||
        foundOffs.ulPDEVoffset == NOT_FOUND_OFFSET)
    {
        print(L"+-----------------------------------------------------------------------+\n");
        print(L"| DDI table was not found. Try increasing the number of scan iterations.|\n");
        print(L"| Current values are: DCOBJ - %-8d PDEV_WIN32K - %-8d           |\n", ofInfo.ulDCOBJiterations, ofInfo.ulPDEViterations);
        print(L"+-----------------------------------------------------------------------+\n");
    }
    else
    {
        print(L"+-------------------------------------------------+\n");
        print(L"| DDI table is found at DCOBJ+0x%04x, PDEV+0x%04x |\n", foundOffs.ulDCOBJoffset, foundOffs.ulPDEVoffset);  
        print(L"+-------------------------------------------------+\n");
    }

    print(L"Uninstall kernel mode component\n");
    UninstallDriver(&g_drvCtx);
    ExitProcess(0);
}


DWORD64 GetSymbolAddress(PWSTR wsImageFilePath, PWSTR wsSymbolName)
{
    if (!wsImageFilePath || !wsSymbolName)
        return 0;

    // we're dynamically linking to our latest and greatest version of DbgHelp.dll that we 
    // previously extracted from resource PE section. This is because of the bunch of reasons,
    // mostly related to dbghelp.dll & symsrv.dll inter-calls.
    HMODULE hDbgHelp = GetModuleHandle(L"dbghelp.dll");
    if (!hDbgHelp)
        hDbgHelp = LoadLibrary(L"dbghelp.dll");
    if (!hDbgHelp)
    {
        LOG_OUTPUT_UM(L"Could not initialize DbgHelp library.");
        return 0;
    }
    SymInitialize_t pSymInitialize = (SymInitialize_t)GetProcAddress(hDbgHelp, "SymInitialize");
    SymSrvGetFileIndexInfo_t pSymSrvGetFileIndexInfo = (SymSrvGetFileIndexInfo_t)GetProcAddress(hDbgHelp, "SymSrvGetFileIndexInfoW");
    SymFindFileInPath_t pSymFindFileInPath = (SymFindFileInPath_t)GetProcAddress(hDbgHelp, "SymFindFileInPath");
    SymLoadModuleEx_t pSymLoadModuleEx = (SymLoadModuleEx_t)GetProcAddress(hDbgHelp, "SymLoadModuleEx");
    SymGetModuleInfo64_t pSymGetModuleInfo64 = (SymGetModuleInfo64_t)GetProcAddress(hDbgHelp, "SymGetModuleInfo64");
    SymGetSymFromName64_t pSymGetSymFromName64 = (SymGetSymFromName64_t)GetProcAddress(hDbgHelp, "SymGetSymFromName64");
    SymGetOptions_t pSymGetOptions = (SymGetOptions_t)GetProcAddress(hDbgHelp, "SymGetOptions");
    SymSetOptions_t pSymSetOptions = (SymSetOptions_t)GetProcAddress(hDbgHelp, "SymSetOptions");
    if (!pSymInitialize || !pSymSrvGetFileIndexInfo || !pSymFindFileInPath || !pSymLoadModuleEx || 
        !pSymGetModuleInfo64 || !pSymGetSymFromName64 || !pSymGetOptions || !pSymSetOptions)
    {
        LOG_OUTPUT_UM(L"Could not initialize DbgHelp library.");
        return 0;
    }

    CSymbolsHandle symHandle(GetCurrentProcess());

    BOOL bRet = pSymInitialize(symHandle, NULL, FALSE); 
    if (!bRet) 
    {
        LOG_OUTPUT_UM(L"Could not initialize DbgHelp library.");
        return 0; 
    }

    // Enable debugging output
    // pSymSetOptions(pSymGetOptions() | SYMOPT_UNDNAME | SYMOPT_DEBUG);

    SYMSRV_INDEX_INFO indexInfo = {0};
    indexInfo.sizeofstruct = sizeof(SYMSRV_INDEX_INFO);
    bRet = pSymSrvGetFileIndexInfo(wsImageFilePath, &indexInfo, 0);
    if (!bRet)
    {
        LOG_OUTPUT_UM(L"Could not obtain file index info for file %s.", wsImageFilePath);
        return 0;
    }

    CHAR sSymbolsFileName[MAX_PATH] = {0};
    _snprintf(sSymbolsFileName, MAX_PATH, "%S", indexInfo.pdbfile);

    CHAR sSymbolsFilePath[MAX_PATH] = {0};
    // The following call ends up in symsrv.dll. This dll must reside in the same directory as dbghelp.dll.
    // On x64 windows OS symsrv.dll should reside in %windir%\SysWOW64 folder.
    bRet = pSymFindFileInPath(symHandle, "http://msdl.microsoft.com/download/symbols", //"http://65.55.10.11/download/symbols"
        sSymbolsFileName, (PVOID)&indexInfo.guid, indexInfo.age, 0, SSRVOPT_GUIDPTR, sSymbolsFilePath, NULL, NULL);
    if (!bRet)
    {
        LOG_OUTPUT_UM(L"Could not locate symbol info on symbols server for file %s. Status: %d", wsImageFilePath, GetLastError());
        return 0;
    }

    DWORD64 dqBaseAddress = 0x100000000; 
    DWORD64 dqSymbolsModuleBase = pSymLoadModuleEx(symHandle, NULL, sSymbolsFilePath, NULL, dqBaseAddress, 0, NULL, 0);
    if (!dqSymbolsModuleBase)
    {
        LOG_OUTPUT_UM(L"Could not load symbols file into the process.");
        return 0;
    }

    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64); 
    bRet = pSymGetModuleInfo64(symHandle, dqSymbolsModuleBase, (PIMAGEHLP_MODULE64)&moduleInfo); 
    if(!bRet) 
    {
        LOG_OUTPUT_UM(L"Could not get symbol information from symbols file.");
        return 0;
    }

    struct CFullSymbol : IMAGEHLP_SYMBOL64 {
        CHAR szRestOfName[512];
    } symInfo;
    ZeroMemory(&symInfo, sizeof(symInfo));
    symInfo.SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    symInfo.MaxNameLength = sizeof(symInfo.szRestOfName);

    PWSTR pDot = wcschr(indexInfo.pdbfile, '.');
    WCHAR wsModuleName[MAX_PATH] = {0};
    memcpy(wsModuleName, indexInfo.pdbfile, (pDot - indexInfo.pdbfile) * 2);

    CHAR sSymbolName[512] = {0};
    _snprintf(sSymbolName, sizeof(sSymbolName), "%S!%S", wsModuleName, wsSymbolName);
    pSymGetSymFromName64(symHandle, sSymbolName, &symInfo);

    symInfo.Address &= 0x00000000ffffffff;
    LOG_OUTPUT_UM(L"%S virtual address is: 0x%x", sSymbolName, symInfo.Address);

    return symInfo.Address;
}

BOOL FillDDIentry(PWSTR wsPathToSymbolsFile, PWSTR wsSymbolName, ULONG ulDDIindex, PDDI_PFNS pDdiPointers)
{
    static ULONG ulDDIfuncLength = 0;

    DWORD64 pSymbol = GetSymbolAddress(wsPathToSymbolsFile, wsSymbolName);
    if (!pSymbol)
    {
        LOG_OUTPUT_UM(L"Could not obtain symbol %s from %s. Check your internet connection.\n", wsSymbolName, wsPathToSymbolsFile);
        return FALSE;
    }
    
    pDdiPointers->ulLength = ++ulDDIfuncLength;
    pDdiPointers->info[ulDDIfuncLength-1].pFunction.QuadPart = pSymbol;
    pDdiPointers->info[ulDDIfuncLength-1].ulIndex = ulDDIindex;
    pDdiPointers->info[ulDDIfuncLength-1].bIsCandidate = 0; // this field will be used later in KM module
    
    return TRUE;
}

BOOL FillDDIpointers(PDDI_PFNS pDdiPointers)
{
    if (!pDdiPointers)
        return FALSE;

    LOG_OUTPUT_UM(L"entering");

    CWow64FsRedirHandler wow64; // Handle Wow64 FS redirection

    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpTextOut", INDEX_DrvTextOut, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpPlgBlt", INDEX_DrvPlgBlt, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpFillPath", INDEX_DrvFillPath, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpLineTo", INDEX_DrvLineTo, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpGradientFill", INDEX_DrvGradientFill, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpCopyBits", INDEX_DrvCopyBits, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpSaveScreenBits", INDEX_DrvSaveScreenBits, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpTransparentBlt", INDEX_DrvTransparentBlt, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpBitBlt", INDEX_DrvBitBlt, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpStretchBlt", INDEX_DrvStretchBlt, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpAlphaBlend", INDEX_DrvAlphaBlend, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpStretchBltROP", INDEX_DrvStretchBltROP, pDdiPointers))
        return FALSE;
    if (!FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"SpStrokePath", INDEX_DrvStrokePath, pDdiPointers))
        return FALSE;
    // the following two symbols from win32k.sys may appear in DDI table on kernels of version 5.x
    // 5.0 - Win 2000
    // 5.1 - Win XP
    // 5.2 - Win Server 2003
    // 6.0 - Win Server 2008
    // 6.1 - Win Server 2008 R2 & Win 7
    // 6.2 - Win Server 2012 & Win 8
    FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"WatchdogDrvTextOut", INDEX_DrvTextOut, pDdiPointers);
    FillDDIentry(L"C:\\Windows\\System32\\win32k.sys", L"WatchdogDrvEnablePDEV", INDEX_DrvEnablePDEV, pDdiPointers);
 
    return TRUE;
}

BOOL GetKernelDcObjPointer(PLARGE_INTEGER pliGdiTablePointer)
{
    if (!pliGdiTablePointer)
        return FALSE;
    
    LOG_OUTPUT_UM(L"entering");

    CWow64FsRedirHandler wow64;
    
    // Try to get symbols for GDI32.dll
    PWSTR wsPathToGdi32Dll = NULL;
    if (wow64.Is64BitOS())
        wsPathToGdi32Dll = L"C:\\Windows\\SysWow64\\GDI32.dll";
    else
        wsPathToGdi32Dll = L"C:\\Windows\\System32\\GDI32.dll";
    DWORD64 pGdiSharedHandleTable = GetSymbolAddress(wsPathToGdi32Dll, L"pGdiSharedHandleTable"); // used to be returned by GDI32!GdiQueryTable()
    if (!pGdiSharedHandleTable)
    {
        LOG_OUTPUT_UM(L"Could not download symbol information for GDI32.dll. Check your internet connection.\n");
        return FALSE;
    }

    PVOID pGdiBase = GetModuleHandle(L"GDI32.dll");
    if (!pGdiBase)
        pGdiBase = LoadLibrary(L"GDI32.dll");
    if (!pGdiBase)
    {
        LOG_OUTPUT_UM(L"Failed to load GDI32.dll with status %d.\n", GetLastError());
        return FALSE;
    }

    // obtain the pointer to GDI shared handle table
    LARGE_INTEGER liGdiQueryTable = {0};
    liGdiQueryTable.QuadPart = pGdiSharedHandleTable;
    ULONG_PTR pGdiTable = *(ULONG_PTR*)((PBYTE)pGdiBase + liGdiQueryTable.LowPart);

    // getting the index of the entry in GDI table
    CAutoHDC hDC(GetDC(NULL), CAutoHDC::FM_RELEASE);   
    HDC dc = hDC.Get();
    int idx = static_cast<int>(reinterpret_cast<__int64>(dc)) & 0xffff; // old approach, seems inaccurate. but is used by windows!!! 
    //PGdiHandle pdc = (PGdiHandle)&dc;
    //int idx = pdc->Index;

    // now get the pointer to the entry in GDI table
    LARGE_INTEGER liKernelDcObj = {0};
    if (wow64.Is64BitOS())
    {
        PGdiTableEntry64 pGdiTableEntry = (PGdiTableEntry64)((PBYTE)pGdiTable + idx * sizeof(GdiTableEntry64));
        liKernelDcObj.QuadPart = pGdiTableEntry->pKernel;
    }
    else
    {
        PGdiTableEntry32 pGdiTableEntry = (PGdiTableEntry32)((PBYTE)pGdiTable + idx * sizeof(GdiTableEntry32));
        liKernelDcObj.LowPart = pGdiTableEntry->pKernel;
    }

    if (!liKernelDcObj.QuadPart)
    {
        LOG_OUTPUT_UM(L"Failed to obtain kernel mode pointer to DCOBJ structure.\n");
        return FALSE;
    }

    pliGdiTablePointer->QuadPart = liKernelDcObj.QuadPart;
    return TRUE;
}

BOOL ExtractRedistDllToCurDir(PWSTR wsDllName, ULONG ulResourceId)
{
    if (!wsDllName)
        return FALSE;

    CWow64FsRedirHandler wow64;

    WCHAR wsCurrentDir[MAX_PATH] = {0};
    // not using GetCurrentDirectory because it may be set to wrong value
    GetModuleFileName(NULL, wsCurrentDir, MAX_PATH);
    PathRemoveFileSpec(wsCurrentDir);

    HRSRC hResource = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(ulResourceId), MAKEINTRESOURCE(RT_RCDATA));
    DWORD dwResourceSize = SizeofResource(GetModuleHandle(NULL), hResource);
    HGLOBAL hLoadedResource = LoadResource(GetModuleHandle(NULL), hResource);
    char* pResourceBody = (char*)LockResource(hLoadedResource);
    if (!pResourceBody || !dwResourceSize)
    {
        LOG_OUTPUT_UM(L"Failed retrieve %s from resources. Status: %d.\n", wsDllName, GetLastError());
        return FALSE;
    }

    WCHAR wsDllFullPath[MAX_PATH] = {0};
    _snwprintf(wsDllFullPath, MAX_PATH, L"%s\\%s", wsCurrentDir, wsDllName);
    HANDLE hDbgHelpFile = CreateFile(wsDllFullPath, FILE_ALL_ACCESS, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (hDbgHelpFile == INVALID_HANDLE_VALUE)
    {
        LOG_OUTPUT_UM(L"Failed to create file %s. Status: %d.\n", wsDllFullPath, GetLastError());
        return FALSE;
    }
    DWORD dwWritten = 0;
    WriteFile(hDbgHelpFile, pResourceBody, dwResourceSize, &dwWritten, 0);
    CloseHandle(hDbgHelpFile);

    // now load Dll with full path
    //LoadLibrary(wsDllFullPath);

    return TRUE;
}

BOOL InstallDriver(PInstDriverContext pDrvCtx)
{
    if (!pDrvCtx)
        return FALSE;

    LOG_OUTPUT_UM(L"entering");
    
    SetPrivilege(L"SeLoadDriverPrivilege", TRUE);
    //ShowProcessPrivileges();

    CWow64FsRedirHandler wow64;

    HRSRC hDriver = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(wow64.Is64BitOS() ? DRIVER64 : DRIVER32), MAKEINTRESOURCE(RT_RCDATA));
    DWORD dwDriverSize = SizeofResource(GetModuleHandle(NULL), hDriver);
    HGLOBAL hResource = LoadResource(GetModuleHandle(NULL), hDriver);
    char* pDriverBody = (char*)LockResource(hResource);
    if (!pDriverBody || !dwDriverSize)
    {
        LOG_OUTPUT_UM(L"Failed retrieve driver from resources. Status: %d.\n", GetLastError());
        return FALSE;
    }

    WCHAR wsTmpPathName[MAX_PATH] = {0};
    GetTempPath(MAX_PATH, wsTmpPathName);
    WCHAR wsTmpFileName[MAX_PATH] = {0};
    GetTempFileName(wsTmpPathName, 0, 0, wsTmpFileName);

    HANDLE hFile = CreateFile(wsTmpFileName, FILE_ALL_ACCESS, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOG_OUTPUT_UM(L"Failed to create file %s", wsTmpFileName);
        return FALSE;
    }

    DWORD dwWritten = 0;
    WriteFile(hFile, pDriverBody, dwDriverSize, &dwWritten, 0);
    CloseHandle(hFile);

    WCHAR wsSubKey[MAX_PATH] = {0};
    _snwprintf(wsSubKey, MAX_PATH, L"system\\currentcontrolset\\services\\%s", DRIVER_NAME);

    HKEY hKey = NULL;
    LONG lRet = RegCreateKey(HKEY_LOCAL_MACHINE, wsSubKey, &hKey);
    if (lRet)
    {
        LOG_OUTPUT_UM(L"Could not create the registry key HKLM\\%s. Not running as Administrator?", wsSubKey);
        DeleteFile(wsTmpFileName);
        return FALSE;
    }

    WCHAR wsImagePath[MAX_PATH] = {0};
    int lengh = _snwprintf(wsImagePath, MAX_PATH, L"\\??\\%s", wsTmpFileName);
    RegSetValueEx(hKey, L"imagepath", 0, REG_EXPAND_SZ, (PBYTE)wsImagePath, (lengh+1)*2);

    DWORD dwFlags = HANDLE_FLAG_INHERIT;
    RegSetValueEx(hKey, L"type", 0, REG_DWORD, (PBYTE)&dwFlags, sizeof(dwFlags));

    RegCloseKey(hKey);

    WCHAR wsNativeRegPath[MAX_PATH] = {0};
    _snwprintf(wsNativeRegPath, MAX_PATH, L"\\registry\\machine\\%s", wsSubKey);

    UNICODE_STRING usNativeRegPath = {0};
    RtlInitUnicodeString(&usNativeRegPath, wsNativeRegPath);
    NTSTATUS status = ZwLoadDriver(&usNativeRegPath);
    if (!NT_SUCCESS(status))
    {
        LOG_OUTPUT_UM(L"Failed to load driver. Native status: %x.\n", status);
        SHDeleteKey(HKEY_LOCAL_MACHINE, wsSubKey);
        DeleteFile(wsTmpFileName);
        return FALSE;
    }

    // fill driver context info
    wcscpy(pDrvCtx->wsFsPathToDriver, wsTmpFileName);
    wcscpy(pDrvCtx->wsRegPathToService, wsSubKey);
    wcscpy(pDrvCtx->wsRegPathToServiceNative, wsNativeRegPath);
    pDrvCtx->bInstalled = TRUE;

    return TRUE;
}

BOOL UninstallDriver(PInstDriverContext pDrvCtx)
{
    if (!pDrvCtx)
        return FALSE;

    LOG_OUTPUT_UM(L"entering");
    
    UNICODE_STRING usNativeRegPath = {0};
    RtlInitUnicodeString(&usNativeRegPath, pDrvCtx->wsRegPathToServiceNative);
    
    ZwUnloadDriver(&usNativeRegPath);
    SHDeleteKey(HKEY_LOCAL_MACHINE, pDrvCtx->wsRegPathToService);
    DeleteFile(pDrvCtx->wsFsPathToDriver);

    memset(pDrvCtx, 0, sizeof(*pDrvCtx));

    return TRUE;
}

// This quick & dirty code is meant to replace wcstok or some better tokenization solution
// based on STL, because we're not linked with CRT and MSVCRT, that's why we haven't one. 
BOOL ObtainCommandLineArgs(ULONG& ulDCOBJiterations, ULONG& ulPDEViterations)
{
    PWSTR wsCommandLine = GetCommandLine();
    PWSTR wsArgs = PathGetArgs(wsCommandLine);
    if (!wsArgs || !wcslen(wsArgs))
    {
        // no arguments, use default 
        ulDCOBJiterations = DEFAULT_DCOBJ_ITERATIONS;
        ulPDEViterations = DEFAULT_PDEV_ITERATIONS;
        return TRUE;
    }

    ULONG ulArgs = 1; // at least one argument

    PWSTR wsIter = wsArgs; 
    while (wsIter)
    {
        wsIter = wcsstr(wsIter, L" ");
        if (!wsIter)
            break;

        ++wsIter;
        if (wcslen(wsIter) || 2 == ulArgs)
            ++ulArgs;
    }

    if (ulArgs != 2) // we only interested in first two arguments
        return FALSE;

    WCHAR wsLocalArgs[MAX_PATH] = {0};
    wcscpy(wsLocalArgs, wsArgs);
    PWSTR wsDelim = wcsstr(wsLocalArgs, L" ");
    *wsDelim = 0;

    ulDCOBJiterations = _wtol(wsLocalArgs);
    ulPDEViterations = _wtol(++wsDelim);

    if (!ulDCOBJiterations || !ulPDEViterations) // non numeric values were passed?
        return FALSE;

    return TRUE;
}

extern "C" int __security_cookie = 0; // TODO: elaborate this

extern "C" int __CxxFrameHandler3(int a, int b, int c, int d)
{    
    LOG_OUTPUT_UM(L"SEH exception occurred");

    if (g_drvCtx.bInstalled)
        UninstallDriver(&g_drvCtx);

    ExitProcess(-1); 
    return 0;
}


BOOL ShowProcessPrivileges()
{
    HANDLE hToken = NULL;
    BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (!bRet)
    {
        OutputDebugString(L"Error: Couldn't open the process token\n");
        return FALSE;
    }

    DWORD dwBytesReturned = 0;
    bRet = GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwBytesReturned);
    if (!dwBytesReturned)
    {
        OutputDebugString(L"Error: Couldn't token privileges information\n");
        return FALSE;
    }

    PTOKEN_PRIVILEGES pTokenPrivileges = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesReturned);
    if (!pTokenPrivileges)
    {
        OutputDebugString(L"Error: Couldn't allocate memory for token privileges information\n");
        return FALSE;
    }

    bRet = GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwBytesReturned, &dwBytesReturned);
    if (!bRet)
    {
        OutputDebugString(L"Error: Couldn't retrieve the privileges of the current process token\n");
        return FALSE;
    }

    OutputDebugString(L"\n");

    WCHAR wsHeaderMsg[MAX_PATH] = {0};
    _snwprintf(wsHeaderMsg, MAX_PATH, L"%-32s %-22s %s\n", L"PRIVILEGE NAME", L"PRIVILEGE STATE", L"DISPLAY NAME");
    OutputDebugString(wsHeaderMsg);
    _snwprintf(wsHeaderMsg, MAX_PATH, L"%-32s %-22s %s\n", L"--------------", L"---------------", L"------------");
    OutputDebugString(wsHeaderMsg);

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i)
    {
        // get privilege name
        WCHAR wsPrivilegeName[MAX_PATH] = {0};
        DWORD dwPrivNameLength = MAX_PATH;
        bRet = LookupPrivilegeName(NULL, &pTokenPrivileges->Privileges[i].Luid, wsPrivilegeName, &dwPrivNameLength);
        if (!bRet)
            continue;

        // get privilege state
        BOOL bUnknownFlags = FALSE;
        PWSTR wsPrivAttribute = NULL;
        if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
            wsPrivAttribute = L"Enabled";
        else if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
            wsPrivAttribute = L"Enabled by default";
        else if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED)
            wsPrivAttribute = L"Removed";
        else if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
            wsPrivAttribute = L"Used for access";
        else if (pTokenPrivileges->Privileges[i].Attributes == 0)
            wsPrivAttribute = L"Disabled";
        else
        {
            bUnknownFlags = TRUE;
            wsPrivAttribute = L"Unknown flags";
        }

        // get privilege display name
        WCHAR wsPrivilegeDisplayName[MAX_PATH] = {0};
        DWORD dwPrivDispNameLength = MAX_PATH;
        DWORD dwLangId = 0;
        bRet = LookupPrivilegeDisplayName(NULL, wsPrivilegeName, wsPrivilegeDisplayName, &dwPrivDispNameLength, &dwLangId);
        if (!bRet)
            continue;

        // compose output
        WCHAR wsPrivilegeInfo[MAX_PATH] = {0};
        if (bUnknownFlags)
            _snwprintf(wsPrivilegeInfo, MAX_PATH - 1, L"%-32s %s, 0x%08x, %s\n", 
            wsPrivilegeName, wsPrivAttribute, pTokenPrivileges->Privileges[i].Attributes, wsPrivilegeDisplayName);
        else
            _snwprintf(wsPrivilegeInfo, MAX_PATH - 1, L"%-32s %-22s %s\n", wsPrivilegeName, wsPrivAttribute, wsPrivilegeDisplayName);

        // show privileges        
        OutputDebugString(wsPrivilegeInfo);
    }

    OutputDebugString(L"\n");

    bRet = CloseHandle(hToken);
    if (!bRet)
    {
        OutputDebugString(L"Error: Couldn't close the process token\n");
        return FALSE;
    }

    HeapFree(GetProcessHeap(), 0, pTokenPrivileges);

    return TRUE;
}

// taken from: 
//      http://msdn.microsoft.com/ru-ru/library/windows/desktop/aa446619(v=vs.85).aspx
// SE constants are available at:
//      http://msdn.microsoft.com/ru-ru/library/windows/desktop/bb530716(v=vs.85).aspx
//
BOOL SetPrivilege(
                  PWSTR lpszPrivilege,  // name of privilege to enable/disable
                  BOOL bEnablePrivilege   // to enable or disable privilege
                  ) 
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        LOG_OUTPUT_UM(L"OpenProcessToken error: %u\n", GetLastError()); 
        return FALSE; 
    }

    LUID luid = {0};
    if (!LookupPrivilegeValue(
            NULL,               // lookup privilege on local system
            lpszPrivilege,      // privilege to lookup 
            &luid))             // receives LUID of privilege
    {
        LOG_OUTPUT_UM(L"LookupPrivilegeValue error: %u\n", GetLastError()); 
        CloseHandle(hToken);
        return FALSE; 
    }

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    { 
        LOG_OUTPUT_UM(L"AdjustTokenPrivileges error: %u\n", GetLastError()); 
        CloseHandle(hToken);
        return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        LOG_OUTPUT_UM(L"Could not obtain the %sprivilege. \n", lpszPrivilege);
        CloseHandle(hToken);
        return FALSE;
    } 

    CloseHandle(hToken);
    return TRUE;
}