#pragma once
#include "SharedDefs.h"

// -----------------------------------------------------------------
// Bitfield member descriptor
// -----------------------------------------------------------------
typedef struct _BITFIELD_MEMBER {
    char  name[64];
    DWORD bitPos;
    DWORD bitLen;
} BITFIELD_MEMBER;

#define MAX_BITFIELD_MEMBERS 64

typedef struct _BITFIELD_LAYOUT {
    BITFIELD_MEMBER members[MAX_BITFIELD_MEMBERS];
    DWORD           count;
    BOOL            valid;
} BITFIELD_LAYOUT;

// -----------------------------------------------------------------
// Globals — defined in main.cpp, declared extern here
// -----------------------------------------------------------------
extern BITFIELD_LAYOUT g_MmVadFlags;
extern BITFIELD_LAYOUT g_MmVadFlags1;
extern BITFIELD_LAYOUT g_MmVadFlags2;
extern BITFIELD_LAYOUT g_MmSectionFlags;

// -----------------------------------------------------------------
// Inline bitfield helpers
// -----------------------------------------------------------------
static inline const BITFIELD_MEMBER* FindBitfieldMember(
    const BITFIELD_MEMBER* arr, DWORD count, const char* name)
{
    for (DWORD i = 0; i < count; i++)
        if (_stricmp(arr[i].name, name) == 0) return &arr[i];
    return NULL;
}

static inline ULONG ExtractBits(ULONG raw, DWORD bitPos, DWORD bitLen) {
    if (!bitLen || bitLen >= 32) return 0;
    return (raw >> bitPos) & ((1u << bitLen) - 1u);
}

static inline ULONG GetFlag(const BITFIELD_LAYOUT* layout, ULONG raw, const char* name) {
    const BITFIELD_MEMBER* m = FindBitfieldMember(layout->members, layout->count, name);
    if (!m || !m->bitLen) return 0;
    return ExtractBits(raw, m->bitPos, m->bitLen);
}

// -----------------------------------------------------------------
// Utility functions — defined in main.cpp
// -----------------------------------------------------------------
const char* ProtectionToStr(PROTECTION prot);
void BuildVadTypeTag(ULONG vf, ULONG ca, BOOLEAN isShort, ULONG mappedViews,
                     ULONG sectionRefs, char* out, size_t outLen);
ULONG BuildVadFlagsRaw(ULONG protection, ULONG vadType, ULONG isPrivate);

// UpdateInitData — passes SymbolsArray explicitly so command files don't need the global
void UpdateInitData(PVOID symbolsArray,
                    const char* sourceProcess, const char* targetProcess,
                    unsigned long long sourceVA, unsigned long long targetVPN,
                    ULONG newProtection);

void GetSymOffsets(PVOID SecBase, size_t SecSize, PVOID FileNameSecBase, SIZE_T FileNameSecSize);
size_t ShowTree(PVOID SecBase, size_t SecSize, PVOID FileNameSecBase, size_t FileNameSecSize,
                unsigned long long* selectedVpns, size_t maxVpns);
