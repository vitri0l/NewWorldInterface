#pragma once
#include "SharedDefs.h"
#include "Globals.h"
#include <vector>

// -----------------------------------------------------------------
// CmdContext — everything commands need to operate.
// Owned by main(), passed by pointer to every command function.
// -----------------------------------------------------------------
struct CmdContext {
    // Process name buffers (writable, max 15 chars + NUL)
    char  sourceProcessBuf[32];
    char  targetProcessBuf[32];
    const char* sourceProcess;   // points into sourceProcessBuf (or NULL)
    const char* targetProcess;   // points into targetProcessBuf (or NULL)

    // Shared memory views
    PVOID SymbolsArray;
    PVOID VADArray;
    PVOID VADArrayFileName;
    PVOID WritePhysArray;
    PVOID ReadPhysArray;
    PVOID VadModifyArray;

    // Events
    HANDLE hEventUSERMODEREADY;
    HANDLE hEventLINK;
    HANDLE hEventUnlink;
    HANDLE hEventINIT;
    HANDLE hEventWRITE_PHYS;
    HANDLE hEventREAD_PHYS;
    HANDLE hEventVAD_INSERT;
    HANDLE hEventVAD_REMOVE;

    // Runtime state
    volatile PVOID sourceVA;
    unsigned long long targetVPN;
    size_t targetVPNSize;
    unsigned long long lastControlAreaPtr;

    // VAD tree index built by 'T', consumed by 'D'
    unsigned long long treeVpns[VAD_MAX_NODES];
    size_t             treeCount;

    // Reusable input scratch buffers (commands share these)
    char inputBuffer[256];
    int  inputIndex;
    int  inputChar;
};

// -----------------------------------------------------------------
// One function per command group.
// Each returns true to stay in the loop, false to exit.
// -----------------------------------------------------------------

// Cmd1Walk   — '1' populate VAD tree
void Cmd1Walk(CmdContext* ctx);

// Cmd2Print  — '2' quick VAD dump
void Cmd2Print(CmdContext* ctx);

// CmdTTree   — 'T' indexed tree view
void CmdTTree(CmdContext* ctx);

// CmdISource / CmdOTarget — 'I','O' set process names
void CmdISource(CmdContext* ctx);
void CmdOTarget(CmdContext* ctx);

// CmdNInsert — 'N' insert VAD node
void CmdNInsert(CmdContext* ctx);

// CmdDDelete — 'D' remove VAD node
void CmdDDelete(CmdContext* ctx);

// CmdVMapView — 'V' map existing CA into another process
void CmdVMapView(CmdContext* ctx);

// CmdFFind — 'F' find all processes sharing a section view
void CmdFFind(CmdContext* ctx);

// CmdEEdit   — 'E' edit memory
void CmdEEdit(CmdContext* ctx);

// CmdQRead   — 'Q' read memory
void CmdQRead(CmdContext* ctx);

// CmdWWritePhys — 'W' write physical
void CmdWWritePhys(CmdContext* ctx);

// CmdRReadPhys  — 'R' read physical
void CmdRReadPhys(CmdContext* ctx);

// Cmd4Link   — '4' link PTE
void Cmd4Link(CmdContext* ctx);

// CmdAProtect — 'A' change protection
void CmdAProtect(CmdContext* ctx);

// CmdPScan   — 'P' pattern scan
void CmdPScan(CmdContext* ctx);

// CmdZDump   — 'Z' minidump via driver
void CmdZDump(CmdContext* ctx);
