#pragma once

// Comment the following symbol in order to switch off debug output.
#define DEBUG_OUTPUT_KM



#define OUTPUT_BUFFER_SIZE 512

int __cdecl _snwprintf(wchar_t *buffer, size_t count, const wchar_t *format, ...);

#ifdef DEBUG_OUTPUT_KM
    #define LOG_OUTPUT_KM(fmt, ...) DbgPrint("OFFSET-FINDER KM: %s - " fmt "\r\n", __FUNCTION__, __VA_ARGS__)
#else 
    #define LOG_OUTPUT_KM(...)
#endif

// Taken from Windows Research Kernel Source Code,
// http://www.microsoft.com/education/facultyconnection/articles/articledetails.aspx?cid=2416&c1=en-us&c2=0

//
// Loader Data Table. Used to track DLLs loaded into an image.
//

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY32 HashLinks;
        struct u{
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        } ;
        struct {
            PVOID LoadedImports;
        };
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;


typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    ULONG64 DllBase;
    ULONG64 EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG   Flags;
    USHORT  LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY64 HashLinks;
        struct {
            ULONG64 SectionPointer;
            ULONG   CheckSum;
        };
    };
    union {
        struct {
            ULONG   TimeDateStamp;
        };
        struct {
            ULONG64 LoadedImports;
        };
    };

    //
    // NOTE : Do not grow this structure at the dump files used a packed
    // array of these structures.
    //

} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;


#if !defined(_AMD64_)
#define LDR_DATA_TABLE_ENTRY        LDR_DATA_TABLE_ENTRY32
#define PLDR_DATA_TABLE_ENTRY       PLDR_DATA_TABLE_ENTRY32
#else
#define LDR_DATA_TABLE_ENTRY        LDR_DATA_TABLE_ENTRY64
#define PLDR_DATA_TABLE_ENTRY       PLDR_DATA_TABLE_ENTRY64
#endif

#if !defined(_AMD64_)
#define LIST_ENTRY                  LIST_ENTRY32
#define PLIST_ENTRY                 PLIST_ENTRY32
#else
#define LIST_ENTRY                  LIST_ENTRY64
#define PLIST_ENTRY                 PLIST_ENTRY64
#endif