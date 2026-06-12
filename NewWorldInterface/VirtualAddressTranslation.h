#pragma once
// System headers
//#include <ntdef.h>
//#include <ntddk.h>
#include <ntifs.h>
// Core
#include "DriverCore.h"
// Memory
#include "MemoryManager.h"
#include "VirtualAddressTranslation.h"
// Communication
#include "EventHandling.h"
#include "SharedMemory.h"
// Common
#include "ProtocolDefinitions.h"
#include "SharedConstants.h"
#include "SharedTypes.h"
// Utils
#include "KernelHelpers.h"
// Process
#include "ProcessManager.h"
#include "VADTreeWalker.h"


// From main.c
VOID ChangeRef(unsigned long long SourceVA, PEPROCESS SourceProcess, unsigned long long SourceCR3,
    unsigned long long TargetVA, PEPROCESS TargetProcess, unsigned long long TargetCR3);

ULONG64 VirtToPhys(unsigned long long addr, PEPROCESS TargetProcess, unsigned long long cr3, BOOLEAN log);

// Walk the x64 page-table hierarchy for `va` using `cr3`.
// All reads are physical (MmCopyMemory MM_COPY_MEMORY_PHYSICAL) — no virtual
// address context is required.  Do NOT call KeStackAttachProcess before this.
// On success fills *outPhysPageBase (page-aligned physical base) and
// *outPageOffset (intra-page byte offset of va).
NTSTATUS WalkPageTablesGetPhysPage(
    unsigned long long va,
    unsigned long long cr3,
    unsigned long long* outPhysPageBase,
    unsigned long long* outPageOffset);