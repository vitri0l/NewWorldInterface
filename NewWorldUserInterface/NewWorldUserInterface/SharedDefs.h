#pragma once
#include <Windows.h>

// -----------------------------------------------------------------
// Shared memory channel names
// -----------------------------------------------------------------
#define MAPPING_NAME_TO                        L"Global\\MySharedMemory"
#define MAPPING_NAME_FROM                      L"Global\\VADSharedMemory"
#define MAPPING_NAME_FROM_FILENAMES            L"Global\\VADSharedMemoryFileNames"
#define MAPPING_NAME_WRITE_PHYS               L"Global\\WritePhysicalMemory"
#define MAPPING_NAME_READ_PHYS                L"Global\\ReadPhysicalMemory"
#define MAPPING_NOTIFICATION_LINK_EVENT       L"Global\\LinkMemory"
#define MAPPING_NOTIFICATION_Unlink_EVENT     L"Global\\UnlinkMemory"
#define MAPPING_NOTIFICATION_INIT_EVENT       L"Global\\InitializeMemory"
#define MAPPING_NOTIFICATION_USERMODEREADY_EVENT L"Global\\UserModeReadEvent"
#define MAPPING_NOTIFICATION_WRITE_PHYS_EVENT L"Global\\WritePhysicalMemoryEvent"
#define MAPPING_NOTIFICATION_READ_PHYS_EVENT  L"Global\\ReadPhysicalMemoryEvent"
#define MAPPING_NAME_VAD_MODIFY               L"Global\\VADModifyRequest"
#define MAPPING_NOTIFICATION_VAD_INSERT_EVENT L"Global\\VADInsertEvent"
#define MAPPING_NOTIFICATION_VAD_REMOVE_EVENT L"Global\\VADRemoveEvent"

// -----------------------------------------------------------------
// Buffer / section sizes
// -----------------------------------------------------------------
#define MAX_FILENAME_SIZE       80
#define MAX_WRITE_BUFFER_SIZE 4096
#define MAX_READ_BUFFER_SIZE  4096
#define VAD_SECTION_SIZE        0x40000   // 256 KB  (~3200 VAD_NODE slots)
#define VAD_FILENAME_SEC_SIZE   0x20000   // 128 KB (~600 VAD_NODE_FILE slots)
#define VAD_MODIFY_SECTION_SIZE 0x10000   //  64 KB
#define VAD_MAX_NODES           512

// -----------------------------------------------------------------
// Kernel-shared structures (byte-identical with SharedTypes.h)
// -----------------------------------------------------------------

typedef struct _INIT {
    CHAR  identifier[4];
    CHAR  sourceProcess[15];
    CHAR  targetProcess[15];
    unsigned long long sourceVA;
    unsigned long long targetVPN;
    unsigned long long NtBaseOffset;
    DWORD KPROCDirectoryTableBaseOffset;
    DWORD EPROCActiveProcessLinksOfsset;
    DWORD EPROCUniqueProcessIdOffset;
    ULONG requestedProtection;
    UCHAR walkMode;      // 0=target  1=source  2=both
    UCHAR reserved[3];
} INIT, *PINIT;

typedef struct _VAD_NODE {
    int                Level;
    PVOID              VADNode;
    PVOID              ParentNode;
    ULONG              Balance;
    unsigned long long StartingVpn;
    unsigned long long EndingVpn;
    unsigned long      Protection;
    ULONG              VadFlagsRaw;
    USHORT             FileOffset;
    ULONG              ControlAreaFlags;
    ULONG64            ControlAreaPtr;
    ULONG              MappedViews;
    ULONG              SectionReferences;
    ULONG              SharedProcessCount;
    BOOLEAN            IsVadShort;
    LIST_ENTRY         ListEntry;
} VAD_NODE, *PVAD_NODE;

typedef struct _VAD_NODE_FILE {
    CHAR FileName[MAX_FILENAME_SIZE];  // _FILE_OBJECT.FileName (relative)
    CHAR DevPath[128];                 // ObQueryNameString full NT path
} VAD_NODE_FILE, *PVAD_NODE_FILE;

typedef struct _WRITE_PHYS_REQUEST {
    CHAR               identifier[4];
    unsigned long long targetVirtualAddress;
    ULONG              offsetInPage;
    ULONG              dataSize;
    UCHAR              data[MAX_WRITE_BUFFER_SIZE];
    BOOLEAN            isValid;
    ULONG              reserved;
} WRITE_PHYS_REQUEST, *PWRITE_PHYS_REQUEST;

typedef struct _READ_PHYS_REQUEST {
    CHAR    identifier[4];
    PVOID   targetVirtualAddress;
    BOOLEAN isValid;
    ULONG   reserved;
    UCHAR   pageData[MAX_READ_BUFFER_SIZE];
} READ_PHYS_REQUEST, *PREAD_PHYS_REQUEST;

typedef struct _VAD_MODIFY_REQUEST {
    CHAR               identifier[4];       // "VINS","VREM","QHNT","OPRC"
    unsigned long long StartingVpn;
    unsigned long long EndingVpn;
    ULONG              Protection;          // VINS: MM prot  / OPRC: desired ACCESS_MASK (0=ALL)
    ULONG              VadTypeRaw;
    SIZE_T             NodeSize;
    BOOLEAN            FreeOnRemove;
    BOOLEAN            SkipCharges;
    BOOLEAN            isValid;
    LONG               Result;
    unsigned long long SuggestedUserVpn;
    unsigned long long SuggestedKernelVpn;
    unsigned long long ControlAreaPtr;
    unsigned long long ReuseCA;
    unsigned long long HandleResult;        // OPRC out: duplicated HANDLE value
} VAD_MODIFY_REQUEST, *PVAD_MODIFY_REQUEST;

// -----------------------------------------------------------------
// SFND: find all processes that have a view of a given _CONTROL_AREA
// Header mirrors VAD_MODIFY_REQUEST — isValid at same offset.
// -----------------------------------------------------------------
#define SFND_MAX_ENTRIES 128
typedef struct _SFND_ENTRY {
    ULONG64 ControlAreaPtr;
    ULONG64 StartingVpn;
    ULONG64 EndingVpn;
    ULONG   Pid;
    ULONG   Protection;
    CHAR    ImageName[16];
    CHAR    FileName[80];
    CHAR    ObjName[128];
    BOOLEAN HasFileName;
    BOOLEAN HasObjName;
} SFND_ENTRY;

typedef struct _SFND_RESULT {
    CHAR        identifier[4];      // "SFND"             offset 0
    ULONG64     TargetControlArea;  // reuses StartingVpn offset 8
    ULONG64     _rsvd0;
    ULONG       _rsvd1;
    ULONG       _rsvd2;
    SIZE_T      _rsvd3;
    BOOLEAN     _rsvd4;
    BOOLEAN     _rsvd5;
    BOOLEAN     isValid;            // same offset as VAD_MODIFY_REQUEST.isValid
    NTSTATUS    Result;
    ULONG       Count;
    SFND_ENTRY  Entries[SFND_MAX_ENTRIES];
} SFND_RESULT, *PSFND_RESULT;

// -----------------------------------------------------------------
// OPRC_RESULT: returned when identifier == "OPRC"
// Contains one process handle + up to OPRC_MAX_THREADS thread handles.
// All handles are duplicated into the requesting (source) process.
// -----------------------------------------------------------------
#define OPRC_MAX_HANDLES 256

typedef struct _OPRC_RESULT {
    CHAR               identifier[4]; // "OPRC"
    BOOLEAN            isValid;
    LONG               Result;
    unsigned long long processHandle;                   // primary process handle
    ULONG              threadCount;
    unsigned long long threadHandles[OPRC_MAX_HANDLES]; // thread handles
} OPRC_RESULT, *POPRC_RESULT;

// -----------------------------------------------------------------
// MMVAD protection enum (kernel encoding, NOT Win32 PAGE_*)
// -----------------------------------------------------------------
typedef enum _PROTECTION {
    _PAGE_NOACCESS          = 0x00,
    _PAGE_READONLY          = 0x01,
    _PAGE_EXECUTE           = 0x02,
    _PAGE_EXECUTE_READ      = 0x03,
    _PAGE_READWRITE         = 0x04,
    _PAGE_WRITECOPY         = 0x05,
    _PAGE_EXECUTE_READWRITE = 0x06,
    _PAGE_EXECUTE_WRITECOPY = 0x07
} PROTECTION;

// -----------------------------------------------------------------
// MI_VAD_TYPE
// -----------------------------------------------------------------
enum MI_VAD_TYPE {
    VadNone                 = 0,
    VadDevicePhysicalMemory = 1,
    VadImageMap             = 2,
    VadAwe                  = 3,
    VadWriteWatch           = 4,
    VadLargePages           = 5,
    VadRotatePhysical       = 6,
    VadLargePageSection     = 7,
};

static inline int    VadTypeIsPrivate(int t)      { return (t==0||t==3||t==4||t==5)?1:0; }
static inline SIZE_T VadNodeSizeForType(int t)    { return VadTypeIsPrivate(t) ? 0x80 : 0x88; }

// -----------------------------------------------------------------
// Symbol table entry (byte-identical with kernel-side SYMBOL)
typedef struct _SYMBOL {
    CHAR name[32];
    unsigned long long offset;
    LIST_ENTRY ListEntry;
} SYMBOL, *PSYMBOL;
