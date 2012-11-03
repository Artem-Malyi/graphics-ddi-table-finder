#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
typedef char* va_list;

#include <wdm.h>
#include <windef.h>
#include <wingdi.h>
#include <winddi.h>

#include "common.h"
#include "km.h"

static PDRIVER_OBJECT           g_pDriverObject     = NULL;
static DDI_OFFSET_FINDER_INFO   g_OfInfo            = {0};
static ULONG                    g_ulDCOBJoffset     = 0;
static ULONG                    g_ulPDEVoffset      = 0;
static ULONG_PTR                g_pPDEVbase         = 0;

static const ULONG NOT_A_DDI_FUNCTION               = -1;

NTSTATUS TmplDispatchCreate         (IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS TmplDispatchClose          (IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS TmplDispatchDeviceControl  (IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
VOID     TmplDriverUnload           (IN PDRIVER_OBJECT pDriverObject);

#pragma pack (push, 1)
typedef struct _PAE_PTE {            // Win XP SP3
    ULONGLONG Valid            : 1;  // Pos 0, 1 Bit
    ULONGLONG Write            : 1;  // Pos 1, 1 Bit
    ULONGLONG Owner            : 1;  // Pos 2, 1 Bit
    ULONGLONG WriteThrough     : 1;  // Pos 3, 1 Bit
    ULONGLONG CacheDisable     : 1;  // Pos 4, 1 Bit
    ULONGLONG Accessed         : 1;  // Pos 5, 1 Bit
    ULONGLONG Dirty            : 1;  // Pos 6, 1 Bit
    ULONGLONG LargePage        : 1;  // Pos 7, 1 Bit
    ULONGLONG Global           : 1;  // Pos 8, 1 Bit
    ULONGLONG CopyOnWrite      : 1;  // Pos 9, 1 Bit
    ULONGLONG Prototype        : 1;  // Pos 10, 1 Bit
    ULONGLONG reserved0        : 1;  // Pos 11, 1 Bit
    ULONGLONG PageFrameNumber  : 26; // Pos 12, 26 Bits
    ULONGLONG reserved1        : 26; // Pos 38, 26 Bits
} PAE_PTE, *PPAE_PTE;

typedef struct _PTE {                // Win XP SP3
    ULONG     Valid            : 1;  // Pos 0, 1 Bit
    ULONG     Write            : 1;  // Pos 1, 1 Bit
    ULONG     Owner            : 1;  // Pos 2, 1 Bit
    ULONG     WriteThrough     : 1;  // Pos 3, 1 Bit
    ULONG     CacheDisable     : 1;  // Pos 4, 1 Bit
    ULONG     Accessed         : 1;  // Pos 5, 1 Bit
    ULONG     Dirty            : 1;  // Pos 6, 1 Bit
    ULONG     LargePage        : 1;  // Pos 7, 1 Bit
    ULONG     Global           : 1;  // Pos 8, 1 Bit
    ULONG     CopyOnWrite      : 1;  // Pos 9, 1 Bit
    ULONG     Prototype        : 1;  // Pos 10, 1 Bit
    ULONG     reserved         : 1;  // Pos 11, 1 Bit
    ULONG     PageFrameNumber  : 20; // Pos 12, 20 Bits
} PTE, *PPTE;

typedef struct _PXE_PTE {            // Win 7 SP1 x64
    ULONGLONG Valid            : 1;  // Pos 0, 1 Bit
    ULONGLONG Write            : 1;  // Pos 1, 1 Bit
    ULONGLONG Owner            : 1;  // Pos 2, 1 Bit
    ULONGLONG WriteThrough     : 1;  // Pos 3, 1 Bit
    ULONGLONG CacheDisable     : 1;  // Pos 4, 1 Bit
    ULONGLONG Accessed         : 1;  // Pos 5, 1 Bit
    ULONGLONG Dirty            : 1;  // Pos 6, 1 Bit
    ULONGLONG LargePage        : 1;  // Pos 7, 1 Bit
    ULONGLONG Global           : 1;  // Pos 8, 1 Bit
    ULONGLONG CopyOnWrite      : 1;  // Pos 9, 1 Bit
    ULONGLONG Prototype        : 1;  // Pos 10, 1 Bit
    ULONGLONG reserved0        : 1;  // Pos 11, 1 Bit
    ULONGLONG PageFrameNumber  : 36; // Pos 12, 36 Bits
    ULONGLONG reserved1        : 4;  // Pos 48, 4 Bits
    ULONGLONG SoftwareWsIndex  : 11; // Pos 52, 11 Bits
    ULONGLONG NoExecute        : 1;  // Pos 63, 1 Bit
} PXE_PTE, *PPXE_PTE;
#pragma pack (pop)

// useful links on VA to PA translation:
// http://technet.microsoft.com/en-us/library/cc736309(WS.10).aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/02/05/understanding-pte-part-1-let-s-get-physical.aspx
#define PDPaddr(va, pa)         ( (PPAE_PTE)(((((ULONG_PTR)va) >> 30) * sizeof(PAE_PTE)) + ((ULONG_PTR)pa)) )
#define PDEaddr(va, pa)         ( (PPTE)((((((ULONG_PTR)va) >> 22) & 0x3ff) * sizeof(PTE)) + ((ULONG_PTR)pa)) )
#define PTEaddr(va, pa)         ( (PPTE)((((((ULONG_PTR)va) >> 12) & 0x3ff) * sizeof(PTE)) + ((ULONG_PTR)pa)) )
#define PDEaddrPae(va, pa)      ( (PPAE_PTE)((((((ULONG_PTR)va) >> 21) & 0x1ff) * sizeof(PAE_PTE)) + ((ULONG_PTR)pa)) )
#define PTEaddrPae(va, pa)      ( (PPAE_PTE)((((((ULONG_PTR)va) >> 12) & 0x1ff) * sizeof(PAE_PTE)) + ((ULONG_PTR)pa)) )
#define TPHaddr(va, pa)         ( (((ULONG_PTR)va) & 0xfff) + ((ULONG_PTR)pa) )
#define TPHaddrLarge(va, pa)    ( ((ULONG_PTR)va & ~0xffc00000) + (((ULONG_PTR)pa) & 0xffc00000) ) // 4mb page
#define TPHaddrLargePae(va, pa) ( ((ULONG_PTR)va & ~0xffe00000) + (((ULONG_PTR)pa) & 0xffe00000) ) // 2mb page

#define PML4addr(va, pa)        ( (PPXE_PTE)((((((ULONG_PTR)va) >> 39) & 0x1ff) * sizeof(PXE_PTE)) + ((ULONG_PTR)pa)) )
#define PDPaddrX64(va, pa)      ( (PPXE_PTE)((((((ULONG_PTR)va) >> 30) & 0x1ff) * sizeof(PXE_PTE)) + ((ULONG_PTR)pa)) )
#define PDEaddrX64(va, pa)      ( (PPXE_PTE)((((((ULONG_PTR)va) >> 21) & 0x1ff) * sizeof(PXE_PTE)) + ((ULONG_PTR)pa)) )
#define PTEaddrX64(va, pa)      ( (PPXE_PTE)((((((ULONG_PTR)va) >> 12) & 0x1ff) * sizeof(PXE_PTE)) + ((ULONG_PTR)pa)) )

#define BitIsSet(var, pos)      ((var) & (1 << (pos)))
#define BitPaePosition          5

BOOLEAN IsPAE()
{
    ULONG64 ulCr4 = __readcr4();
    //LOG_OUTPUT_KM("CR4: 0x%x", ulCr4);
    return (BitIsSet(ulCr4, BitPaePosition)) ? TRUE : FALSE;
}

ULONGLONG DumpQwordPhysical(PVOID physicalAddress)
{
    ULONGLONG dumpedQword = 0;
    PPHYSICAL_ADDRESS pPa = NULL;
    PHYSICAL_ADDRESS pa = {0};
    pa.QuadPart = (LONGLONG)physicalAddress;

    pPa = MmMapIoSpace(pa, sizeof(pa), MmNonCached);
    if (!pPa)
        return 0;    
    dumpedQword = pPa->QuadPart;
    MmUnmapIoSpace(pPa, sizeof(pa)); 

    return dumpedQword;
}

ULONG DumpDwordPhysical(PVOID physicalAddress)
{
    ULONG dumpedDword = 0;
    PULONG pPa = NULL;
    PHYSICAL_ADDRESS pa = {0};
    pa.QuadPart = (LONGLONG)physicalAddress;

    pPa = MmMapIoSpace(pa, sizeof(pa), MmNonCached);
    if (!pPa)
        return 0;  
    dumpedDword = *pPa;
    MmUnmapIoSpace(pPa, sizeof(pa)); 

    return dumpedDword;
}

#ifdef _WIN64
BOOLEAN IsAddressValid(PVOID pAddress)
{
    PVOID va        = pAddress;
    ULONG_PTR pml4t = 0;    // pointer to Page Map Level 4 Table
    PPXE_PTE pdpt   = NULL; // pointer to Page Directory Pointer Table
    PPXE_PTE pdpte  = NULL; // pointer to Page Directory Pointer Table Entry
    PPXE_PTE pdte   = NULL; // pointer to Page Directory Table Entry
    PPXE_PTE pte    = NULL; // pointer to Page Table Entry
    ULONG_PTR paddr = 0;    // translated physical address
    ULONGLONG pa    = 0;   
    PVOID pTmp = NULL;

    // 1. read PML4 table address from cr3 register
    pml4t = __readcr3() & 0xffffffe0;

    // 2. get the Page Directory Pointer Table 
    pa = DumpQwordPhysical(PML4addr(va, pml4t));
    pdpt = (PPXE_PTE)&pa;
    if (!pdpt->Valid)
        return FALSE;
    pa &= 0xfffff000;

    // 3. get the Page Directory Pointer Table Entry
    pa = DumpQwordPhysical(PDPaddrX64(va, pa));
    pdpte = (PPXE_PTE)&pa;
    if (!pdpte->Valid)
        return FALSE;
    pa &= 0xfffff000;

    // 4. get the Page Table Entry
    pa = DumpQwordPhysical(PDEaddrX64(va, pa));
    pdte = (PPXE_PTE)&pa;
    if (!pdte->Valid)
        return FALSE;
    pa &= 0xfffff000;

    // 5. get the Page Directory Table Entry
    pa = DumpQwordPhysical(PTEaddrX64(va, pa));
    pte = (PPXE_PTE)&pa;
    if (!pte->Valid)
        return FALSE;
    pa &= 0xfffff000;

    // 6. get Translated Physical Address
    paddr = TPHaddr(va, pa);
    // this must be valid physical address

    return TRUE;
}
#else // _X86
BOOLEAN IsAddressValid(PVOID pAddress)
{
    PVOID va        = pAddress;
    ULONG_PTR pdpt  = 0;    // pointer to Page Directory Pointer Table
    PPTE pdpte      = NULL; // pointer to Page Directory Pointer Table Entry
    PPTE pdte       = NULL; // pointer to Page Directory Table Entry
    PPTE pte        = NULL; // pointer to Page Table Entry
    ULONG_PTR paddr = 0;    // translated physical address
    ULONGLONG pa    = 0;   

    // 1. read PDP address from cr3 register
    pdpt = __readcr3() & 0xffffffe0;

    if (IsPAE()) // handle physical address extension paging
    {
        // 2. get the Page Directory Pointer Table Entry
        pa = DumpQwordPhysical(PDPaddr(va, pdpt));
        pdpte = (PPTE)&pa;
        if (!pdpte->Valid)
            return FALSE;
        pa &= 0xfffff000;

        // 3. get the Page Directory Table Entry
        pa = DumpQwordPhysical(PDEaddrPae(va, pa));
        pdte = (PPTE)&pa;
        if (!pdte->Valid)
            return FALSE;
        if (pdte->LargePage)
        {
            // get Translated Physical Address of the large page
            paddr = TPHaddrLargePae(va, pa);
            // this must be valid physical address
            return TRUE;
        }
        pa &= 0xfffff000;

        // 4. get the Page Table Entry
        pa = DumpQwordPhysical(PTEaddrPae(va, pa));
        pte = (PPTE)&pa;
        if (!pte->Valid)
            return FALSE;
        pa &= 0xfffff000;

        // 5. get Translated Physical Address
        paddr = TPHaddr(va, pa);
        // this must be valid physical address
    }
    else // handle 32-bit paging
    {
        // 2. get the Page Directory Table Entry
        pa = DumpDwordPhysical(PDEaddr(va, pdpt));
        pdte = (PPTE)&pa;
        if (!pdte->Valid)
            return FALSE;
        if (pdte->LargePage)
        {
            // get Translated Physical Address of the large page
            paddr = TPHaddrLarge(va, pa);
            // this must be valid physical address
            return TRUE;
        }
        pa &= 0xfffff000;

        // 3. get the Page Table Entry
        pa = DumpDwordPhysical(PTEaddr(va, pa));
        pte = (PPTE)&pa;
        if (!pte->Valid)
            return FALSE;
        pa &= 0xfffff000;
        
        // 4. get Translated Physical Address
        paddr = TPHaddr(va, pa);
        // this must be valid physical address
    }

    return TRUE;
}
#endif // _X86

BOOLEAN IsDDItable(ULONG_PTR DDItable)
{
    ULONG i = 0;
    PULONG_PTR pDDItable = (PULONG_PTR)DDItable;
        
    if (!pDDItable)
        return FALSE;
    
    LOG_OUTPUT_KM("checking 0x%llx as a candidate for DDI table", pDDItable);

    // according to winddi.h the first 5 functions in DDI table are required,
    // so if they're empty, it's not a DDI table
    if (!pDDItable[INDEX_DrvEnablePDEV] &&
        !pDDItable[INDEX_DrvCompletePDEV] &&
        !pDDItable[INDEX_DrvDisablePDEV] &&
        !pDDItable[INDEX_DrvEnableSurface] &&
        !pDDItable[INDEX_DrvDisableSurface])
    {
        return FALSE;
    }

    for (i = 0; i < g_OfInfo.ddiPfns.ulLength; ++i)
    {
        // skip DDI function candidate found earlier
        if (g_OfInfo.ddiPfns.info[i].bIsCandidate)
            continue;
        
        if (pDDItable[g_OfInfo.ddiPfns.info[i].ulIndex] != (ULONG_PTR)g_OfInfo.ddiPfns.info[i].pFunction.QuadPart)
            continue;
        
        // if we have a match for at least two functions inside DDI table, 
        // then we assume this is indeed a DDI table.
        LOG_OUTPUT_KM("DDI table is found at address 0x%llx", pDDItable);
        return TRUE;
    }

    return FALSE;
}

BOOLEAN ScanDDItable(ULONG_PTR pDDIFunction)
{
    ULONG ulDDIindex = 0, ulDDItableOffset = 0;
    ULONG_PTR pDDItable = 0;
    ULONG i = 0;

    ulDDIindex = NOT_A_DDI_FUNCTION;
    for (i = 0; i < g_OfInfo.ddiPfns.ulLength; ++i)
    {
        if (pDDIFunction != (ULONG_PTR)g_OfInfo.ddiPfns.info[i].pFunction.QuadPart)
            continue;
        
        ulDDIindex = g_OfInfo.ddiPfns.info[i].ulIndex;
        // we're setting this flag to TRUE in order to skip this entry in a final
        // check for DDI table in IsDDItable routine.
        g_OfInfo.ddiPfns.info[i].bIsCandidate = TRUE; 

        LOG_OUTPUT_KM("[0x%04x, 0x%04x] - examining 0x%llx: DDI function #%d is recognized", 
            g_ulDCOBJoffset, g_ulPDEVoffset, pDDIFunction, ulDDIindex);

        break;
    }

    if (NOT_A_DDI_FUNCTION == ulDDIindex)
    {
        LOG_OUTPUT_KM("[0x%04x, 0x%04x] - address 0x%llx is not a Win32k DDI function of interest", g_ulDCOBJoffset, g_ulPDEVoffset, pDDIFunction); 
        return FALSE;
    }

    ulDDItableOffset = g_ulPDEVoffset - (ulDDIindex * sizeof(ULONG_PTR));
    LOG_OUTPUT_KM("[0x%04x, 0x%04x] - a candidate for DDI table is found at offset 0x%04x in PDEV_WIN32K", g_ulDCOBJoffset, g_ulPDEVoffset, ulDDItableOffset);

    pDDItable = g_pPDEVbase + ulDDItableOffset;
    if (!IsDDItable(pDDItable))
    {
        // if not a DDI table then clear the Candidate flag for a function
        for (i = 0; i < g_OfInfo.ddiPfns.ulLength; ++i)
            g_OfInfo.ddiPfns.info[i].bIsCandidate = FALSE;
        return FALSE;
    }

    g_ulPDEVoffset = ulDDItableOffset;
    return TRUE;
}

BOOLEAN ScanPDEV(ULONG_PTR pPdevObj)
{
    PULONG_PTR pIter = NULL;
    ULONG i = 0;
    PMDL pMdl = NULL;
    g_ulPDEVoffset = 0;

    // The code below will try to access g_OfInfo.ulPDEViterations of memory pointers starting 
    // from pPdevObj. Since these pointers are totally arbitrary, we must lock the virtual pages in memory.
    // pPdevObj - pPdevObj+(g_OfInfo.ulPDEViterations*sizeof(ULONG_PTR))
    pMdl = IoAllocateMdl((PVOID)pPdevObj, g_OfInfo.ulPDEViterations * sizeof(ULONG_PTR), FALSE, FALSE, NULL);
    if (!pMdl)
        return FALSE;
    MmBuildMdlForNonPagedPool(pMdl);
    pIter = MmMapLockedPages(pMdl, KernelMode);

    for (i = 0; i < g_OfInfo.ulPDEViterations; ++i)
    {
        ULONG_PTR pAddress = pIter[i];
        if (IsAddressValid((PVOID)pAddress)) 
        {
            LOG_OUTPUT_KM("[0x%04x, 0x%04x] - trying address 0x%llx: is valid", g_ulDCOBJoffset, g_ulPDEVoffset, pAddress);        
            if (ScanDDItable(pAddress))
            {
                MmUnmapLockedPages(pIter, pMdl);
                IoFreeMdl(pMdl);
                return TRUE;
            }
        }
        else 
            LOG_OUTPUT_KM("[0x%04x, 0x%04x] - trying address 0x%llx: is invalid", g_ulDCOBJoffset, g_ulPDEVoffset, pAddress);  
        g_ulPDEVoffset += sizeof(ULONG_PTR);
    }

    MmUnmapLockedPages(pIter, pMdl);
    IoFreeMdl(pMdl);
    return FALSE;
}

BOOLEAN ScanDCOBJ(ULONG_PTR pKernelDcObj)
{
    PULONG_PTR pIter = NULL;
    ULONG i = 0;
    PMDL pMdl = NULL;
    g_ulDCOBJoffset = 0;
    g_pPDEVbase = 0;

    //__debugbreak();

    //IsAddressValid((PVOID)0x804d7000);

    pMdl = IoAllocateMdl((PVOID)pKernelDcObj, g_OfInfo.ulDCOBJiterations * sizeof(ULONG_PTR), FALSE, FALSE, NULL);
    if (!pMdl)
        return FALSE;
    MmBuildMdlForNonPagedPool(pMdl);
    pIter = MmMapLockedPages(pMdl, KernelMode);

    // TODO: to fix page faults, try: 
	// 1. MmMapLockedPages ? : +
	// 2. Play with MmPagedPoolStart, MmPagedPoolEnd, MmNonPagedPoolStart, 
	//		MmNonPagedPoolExpansionStart, MnNonPagedPoolEnd, 
	//		MmSystemCacheStart, MmSystemCacheEnd, MmSystemCacheEnd, ...
    // 3. Stop all other processors ?

    for (i = 0; i < g_OfInfo.ulDCOBJiterations; ++i)
    {
        ULONG_PTR pAddress = pIter[i];
        if (IsAddressValid((PVOID)pAddress)) 
        {
            LOG_OUTPUT_KM("trying address 0x%llx: is valid", pAddress);
            g_pPDEVbase = pAddress;
            if (ScanPDEV(pAddress))
            {
                MmUnmapLockedPages(pIter, pMdl);
                IoFreeMdl(pMdl);
                return TRUE;
            }
        }
        else 
            LOG_OUTPUT_KM("trying address 0x%llx: is invalid", pAddress);
        g_ulDCOBJoffset += sizeof(ULONG_PTR);
    }

    MmUnmapLockedPages(pIter, pMdl);
    IoFreeMdl(pMdl);
    return FALSE;
}

/////////////////////////////////////////////////////////////////////////////////////
//
// Name:	KeGetModuleHandle
//
// Notes:	Performs search of the given module in the loaded drivers list. The
//			algorithm is based on the fact that LPVOID PDRIVER_OBJECT->DriverSection
//			is actually a pointer to LDR_DATA_TABLE_ENTRY structure.	
//			Note also, that this method allows to retrieve the image base addresses
//			of another loaded drivers, like ntfs.sys of tdi.sys.
//
// Params:	pusModuleName - the name of the module.
// 
// Returns: Image base of the found module.
//
/////////////////////////////////////////////////////////////////////////////////////
PVOID KeGetModuleHandle(PVOID pDriverSection, PCUNICODE_STRING pusModuleName)
{
    PLDR_DATA_TABLE_ENTRY pLdrCurrentEntry = NULL;
    PLDR_DATA_TABLE_ENTRY pLdrEntryListHead = NULL;
    PVOID pModuleBase = NULL;

    if (!pusModuleName || !pDriverSection)
        return NULL;

    __try
    {
        pLdrEntryListHead = (PLDR_DATA_TABLE_ENTRY)pDriverSection;
        pLdrCurrentEntry = (PLDR_DATA_TABLE_ENTRY)pLdrEntryListHead->InLoadOrderLinks.Blink;

        while (pLdrCurrentEntry != pLdrEntryListHead)
        {        
            //LOG_DEBUG_OUTPUT(L"%s is loaded at 0x%x", pLdrCurrentEntry->BaseDllName.Buffer, pLdrCurrentEntry->DllBase);

            if (RtlEqualUnicodeString((PCUNICODE_STRING)&pLdrCurrentEntry->BaseDllName, pusModuleName, TRUE))
            {
                pModuleBase = (PVOID)pLdrCurrentEntry->DllBase;
                break;
            }

            pLdrCurrentEntry = (PLDR_DATA_TABLE_ENTRY)pLdrCurrentEntry->InLoadOrderLinks.Blink;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_OUTPUT_KM("SEH exception occured");
        return NULL;
    }

    return pModuleBase;
}

BOOLEAN NormalizeDDIpointers(PDDI_PFNS pDDIpfns)
{
    PVOID pWin32kBase = NULL;
    UNICODE_STRING usWin32kModuleName = {0};
    ULONG i = 0;

    if (!pDDIpfns)
        return FALSE;

    RtlInitUnicodeString(&usWin32kModuleName, L"win32k.sys");
    pWin32kBase = KeGetModuleHandle(g_pDriverObject->DriverSection, &usWin32kModuleName);
    if (!pWin32kBase)
    {
        LOG_OUTPUT_KM("Could not find the image base of win32k.sys. Cannot continue.");
        return FALSE;
    }

    for (i = 0; i < pDDIpfns->ulLength; ++i)
        pDDIpfns->info[i].pFunction.QuadPart = (LONGLONG)((PUCHAR)pWin32kBase + pDDIpfns->info[i].pFunction.QuadPart);

    return TRUE;
}

BOOLEAN SearchForOffsets(PDDI_OFFSET_FINDER_INFO pOfInfo)
{
    ULONG_PTR pKernelDcObj = 0;
    BOOLEAN bSuccess = FALSE;
    KIRQL oldIrql = -1;
    
    if (!pOfInfo)
        return FALSE;

    LOG_OUTPUT_KM("Target OS %s, IRQL: %d", IsPAE() ? "uses PAE" : "doesn't use PAE", KeGetCurrentIrql());
    
    // 1. find the win32k.sys base and update VAs in the DDI pointers table
    bSuccess = NormalizeDDIpointers(&pOfInfo->ddiPfns);
    if (!bSuccess)
    {
        LOG_OUTPUT_KM("Could not normalize Win32k DDI function pointers");
        return FALSE;
    }
    
#ifdef _WIN64
    pKernelDcObj = g_OfInfo.pKernelDcObj.QuadPart;
#else 
    pKernelDcObj = g_OfInfo.pKernelDcObj.LowPart;
#endif

    // 2. scan kernel memory space in order to find DDI table in PDEV_Win32k structure
    LOG_OUTPUT_KM("Start scanning from 0x%x", pKernelDcObj);
    
    bSuccess = ScanDCOBJ(pKernelDcObj);
    
    return bSuccess;
}


NTSTATUS TmplDriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
    NTSTATUS        	status = STATUS_SUCCESS;
    UNICODE_STRING  	usDeviceName = {0};
    UNICODE_STRING  	usSymlinkName = {0};
    PDEVICE_OBJECT  	pDeviceObject = NULL;

    LOG_OUTPUT_KM("Entering");

    RtlInitUnicodeString(&usDeviceName, L"\\Device\\" DRIVER_NAME);
    status = IoCreateDevice(pDriverObject, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
    if (!NT_SUCCESS(status))
        return status;

    pDriverObject->MajorFunction[IRP_MJ_CREATE]         = TmplDispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]          = TmplDispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TmplDispatchDeviceControl;
    pDriverObject->DriverUnload                         = TmplDriverUnload;
    
    // store DRIVER_OBJECT pointer for KeGetModuleHandle routine
    g_pDriverObject = pDriverObject;

    RtlInitUnicodeString(&usSymlinkName, L"\\DosDevices\\" DRIVER_NAME);
    status = IoCreateSymbolicLink(&usSymlinkName, &usDeviceName);
    if (!NT_SUCCESS(status))
        IoDeleteDevice(pDeviceObject);

    return status;
}


VOID TmplDriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
    PDEVICE_OBJECT pDeviceObject = pDriverObject->DeviceObject;
    UNICODE_STRING usSymlinkName = {0};

    LOG_OUTPUT_KM("Entering");

    RtlInitUnicodeString(&usSymlinkName, L"\\DosDevices\\" DRIVER_NAME);
    IoDeleteSymbolicLink(&usSymlinkName);
    if (pDeviceObject != NULL)
        IoDeleteDevice(pDeviceObject);
}


NTSTATUS TmplDispatchClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_OUTPUT_KM("Entering");

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}


NTSTATUS TmplDispatchCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;

    LOG_OUTPUT_KM("Entering");

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}


NTSTATUS TmplDispatchDeviceControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
    PIO_STACK_LOCATION  pIosl = NULL;
    NTSTATUS            status = STATUS_SUCCESS;
    ULONG               ulInBufLength = 0;
    ULONG               ulOutBufLength = 0;

    LOG_OUTPUT_KM("entering");

    pIosl = IoGetCurrentIrpStackLocation(pIrp);
    ulInBufLength = pIosl->Parameters.DeviceIoControl.InputBufferLength;
    ulOutBufLength = pIosl->Parameters.DeviceIoControl.OutputBufferLength;

    switch (pIosl->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_PASS_INFO:
        if ( ulInBufLength == sizeof(DDI_OFFSET_FINDER_INFO) &&
            ulOutBufLength == sizeof(DDI_FOUND_OFFSETS))
        {
            __try
            {
                PDDI_OFFSET_FINDER_INFO pOfInfo = (PDDI_OFFSET_FINDER_INFO)pIrp->AssociatedIrp.SystemBuffer;
                PDDI_FOUND_OFFSETS pFoundOffs = (PDDI_FOUND_OFFSETS)pIrp->AssociatedIrp.SystemBuffer;
                BOOLEAN bSuccess = FALSE;

                if (pOfInfo && pFoundOffs)
                {
                    // store the info passed from UM module in a global structure
                    memset(&g_OfInfo, 0, sizeof(g_OfInfo));
                    memcpy(&g_OfInfo, pOfInfo, sizeof(g_OfInfo));
    
                    // perform the scan
                    bSuccess = SearchForOffsets(&g_OfInfo);
                    memset(pOfInfo, 0, sizeof(*pOfInfo));
                    if (!bSuccess)
                    {
                        pFoundOffs->ulDCOBJoffset = NOT_FOUND_OFFSET;
                        pFoundOffs->ulPDEVoffset = NOT_FOUND_OFFSET;
                    }
                    else
                    {
                        pFoundOffs->ulDCOBJoffset = g_ulDCOBJoffset;
                        pFoundOffs->ulPDEVoffset = g_ulPDEVoffset;
                    }
                    pIrp->IoStatus.Information = sizeof(DDI_FOUND_OFFSETS);
                    status = STATUS_SUCCESS;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                LOG_OUTPUT_KM("SEH exception occurred");
            }
        }
        break;        
    default:        
        pIrp->IoStatus.Information = 0;
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}