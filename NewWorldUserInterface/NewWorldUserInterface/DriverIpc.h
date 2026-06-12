#pragma once
#include "SharedDefs.h"

// -----------------------------------------------------------------
// IpcCtx — minimal view of CmdContext needed by the IPC helpers.
// Commands pass their CmdContext* directly (it is a superset).
// -----------------------------------------------------------------
struct IpcCtx {
    HANDLE hEventVAD_INSERT;
    HANDLE hEventINIT;
    PVOID  VadModifyArray;
    PVOID  SymbolsArray;
    const char* sourceProcess;
    const char* targetProcess;
    volatile PVOID sourceVA;
};

// -----------------------------------------------------------------
// Ipc_SetKernelContext
//   Writes INIT data and signals hEventINIT so the driver picks up
//   the new source/target before any command is issued.
//   Returns true on success.
// -----------------------------------------------------------------
bool Ipc_SetKernelContext(IpcCtx* ipc, const char* source, const char* target);

// -----------------------------------------------------------------
// Ipc_OpenProcess
//   Sends OPRC — driver opens targetProcess with PROCESS_ALL_ACCESS
//   and duplicates the handle into our process.
//   On success: *hOut receives the handle, *pidOut receives the PID.
//   Returns true on success.
// -----------------------------------------------------------------
bool Ipc_OpenProcess(IpcCtx* ipc, HANDLE* hOut, DWORD* pidOut);

// -----------------------------------------------------------------
// Ipc_ClearProtection
//   Sends PPRT with Protection=0 — driver zeroes EPROCESS.Protection
//   and returns the original byte in *savedOut.
//   Returns true if the command was accepted (even if protection was 0).
// -----------------------------------------------------------------
bool Ipc_ClearProtection(IpcCtx* ipc, UCHAR* savedOut);

// -----------------------------------------------------------------
// Ipc_RestoreProtection
//   Sends PPRT with Protection=saved — driver writes the byte back.
//   No-op if saved == 0. Returns true on success.
// -----------------------------------------------------------------
bool Ipc_RestoreProtection(IpcCtx* ipc, UCHAR saved);

// -----------------------------------------------------------------
// Ipc_FindSectionViewers
//   Sends SFND — driver walks all EPROCESS VAD trees and returns
//   every process that has a VAD backed by targetCA.
//   Results written into *out (caller-allocated).
//   Returns true if the command completed (check out->Result for status).
// -----------------------------------------------------------------
bool Ipc_FindSectionViewers(IpcCtx* ipc, ULONG64 targetCA, SFND_RESULT* out);
