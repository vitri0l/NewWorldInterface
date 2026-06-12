#include "Commands.h"
#include "DriverIpc.h"
#include "UI.h"
#include <conio.h>
#include <cctype>

// ── helpers ────────────────────────────────────────────────────────
static void ReadHex(CmdContext* ctx, const char* prompt) {
    printf("%s", prompt); fflush(stdout);
    memset(ctx->inputBuffer, 0, sizeof(ctx->inputBuffer));
    ctx->inputIndex = 0;
    while ((ctx->inputChar = _getch()) != '\r' && ctx->inputChar != '\n') {
        if (ctx->inputChar == '\b' && ctx->inputIndex > 0)
            { ctx->inputBuffer[--ctx->inputIndex] = 0; printf("\b \b"); }
        else if (isxdigit(ctx->inputChar) && ctx->inputIndex < (int)sizeof(ctx->inputBuffer)-1)
            { ctx->inputBuffer[ctx->inputIndex++] = (char)ctx->inputChar; printf("%c", ctx->inputChar); }
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex] = 0;
}

static void ReadDec(CmdContext* ctx, const char* prompt) {
    printf("%s", prompt); fflush(stdout);
    memset(ctx->inputBuffer, 0, sizeof(ctx->inputBuffer));
    ctx->inputIndex = 0;
    while ((ctx->inputChar = _getch()) != '\r' && ctx->inputChar != '\n') {
        if (ctx->inputChar == '\b' && ctx->inputIndex > 0)
            { ctx->inputBuffer[--ctx->inputIndex] = 0; printf("\b \b"); }
        else if (isdigit(ctx->inputChar) && ctx->inputIndex < (int)sizeof(ctx->inputBuffer)-1)
            { ctx->inputBuffer[ctx->inputIndex++] = (char)ctx->inputChar; printf("%c", ctx->inputChar); }
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex] = 0;
}

// ─────────────────────────────────────────────────────────────────
// 'N' — insert a new (ghost) VAD node
// ─────────────────────────────────────────────────────────────────
void CmdNInsert(CmdContext* ctx)
{
    unsigned long long newStart = 0, newEnd = 0;
    ULONG newProt = 0x04;

    UCHAR curWalkMode  = ((PINIT)ctx->SymbolsArray)->walkMode;
    const char* activeProc = (curWalkMode == 1)
        ? (ctx->sourceProcess ? ctx->sourceProcess : "(source not set)")
        : (ctx->targetProcess ? ctx->targetProcess : "(target not set)");

    // ── QHNT: suggest next free VPN ────────────────────────────────
    {
        PVAD_MODIFY_REQUEST q = (PVAD_MODIFY_REQUEST)ctx->VadModifyArray;
        memset(q, 0, sizeof(VAD_MODIFY_REQUEST));
        memcpy(q->identifier, "QHNT", 4);
        q->isValid = TRUE;
        if (SetEvent(ctx->hEventVAD_INSERT)) {
            Sleep(300);
            if (!q->isValid) {
                printf("[+] Process: '%s'\n", activeProc);
                if (q->SuggestedUserVpn || q->SuggestedKernelVpn) {
                    printf("[+] Suggested free VPN slots:\n");
                    if (q->SuggestedUserVpn)
                        printf("    [U] User  : 0x%016llx  (VA 0x%016llx)\n",
                               q->SuggestedUserVpn, q->SuggestedUserVpn * 0x1000ULL);
                    if (q->SuggestedKernelVpn)
                        printf("    [K] Kernel: 0x%016llx  (VA 0x%016llx)\n",
                               q->SuggestedKernelVpn, q->SuggestedKernelVpn * 0x1000ULL);
                    printf("    [M] Enter manually\n    Choice [U/K/M]: "); fflush(stdout);
                    int hc = _getch(); printf("%c\n", hc);
                    if ((hc=='u'||hc=='U') && q->SuggestedUserVpn)   newStart = q->SuggestedUserVpn;
                    if ((hc=='k'||hc=='K') && q->SuggestedKernelVpn) newStart = q->SuggestedKernelVpn;
                } else {
                    printf("[!] No VPN suggestion (result=0x%08lx)\n", (ULONG)q->Result);
                }
            } else {
                printf("[!] QHNT timed out\n");
            }
        }
    }

    if (newStart == 0) {
        ReadHex(ctx, "Enter StartingVpn (hex): 0x");
        if (!ctx->inputIndex) { printf("[-] No StartingVpn\n"); return; }
        newStart = strtoull(ctx->inputBuffer, NULL, 16);
    }

    ReadDec(ctx, "Enter region size in pages (decimal): ");
    unsigned long long sizePgs = (ctx->inputIndex > 0) ? strtoull(ctx->inputBuffer, NULL, 10) : 1;
    if (sizePgs == 0) sizePgs = 1;
    newEnd = newStart + sizePgs - 1;
    printf("[*] Region VPN 0x%llx - 0x%llx  (%llu page(s), %llu KB)\n",
           newStart, newEnd, sizePgs, sizePgs * 4);

    ReadHex(ctx, "Protection (hex MMVAD, e.g. 04=RW 01=RO) [04]: 0x");
    if (ctx->inputIndex > 0) newProt = (ULONG)strtoul(ctx->inputBuffer, NULL, 16);
    if (newProt == 0) newProt = 0x04;

    printf("VadType: [0]Private [2]Image [5]LrgPage [8]Section [9]Reserved [0]: ");
    fflush(stdout);
    int tc = _getch(); printf("%c\n", tc);
    int vadTypeChoice = (tc >= '0' && tc <= '9') ? (tc - '0') : 0;

    BOOLEAN skipCharges = FALSE;
    ULONG   isPrivate   = 1;
    MI_VAD_TYPE chosenType = (MI_VAD_TYPE)vadTypeChoice;
    if (vadTypeChoice == 8) { chosenType = VadNone; isPrivate = 0; }
    else if (vadTypeChoice == 9) { chosenType = VadNone; isPrivate = 1; skipCharges = TRUE; }
    else { isPrivate = VadTypeIsPrivate((int)chosenType) ? 1 : 0; }

    ULONG vadFlags = BuildVadFlagsRaw(newProt, (ULONG)chosenType, isPrivate);
    SIZE_T nodeSize = isPrivate ? 0x80 : 0x88;
    printf("[*] VadType=%u  Private=%u  FlagsRaw=0x%08lx  NodeSize=0x%zx\n",
           (ULONG)chosenType, isPrivate, vadFlags, nodeSize);

    PVAD_MODIFY_REQUEST vReq = (PVAD_MODIFY_REQUEST)ctx->VadModifyArray;
    memset(vReq, 0, sizeof(VAD_MODIFY_REQUEST));
    memcpy(vReq->identifier, "VINS", 4);
    vReq->StartingVpn = newStart;
    vReq->EndingVpn   = newEnd;
    vReq->Protection  = newProt;
    vReq->VadTypeRaw  = vadFlags;
    vReq->NodeSize    = nodeSize;
    vReq->SkipCharges = skipCharges;
    vReq->isValid     = TRUE;

    printf("[*] Inserting into '%s'  VPN 0x%llx-0x%llx  prot=0x%lx\n",
           activeProc, newStart, newEnd, newProt);
    if (SetEvent(ctx->hEventVAD_INSERT)) {
        Sleep(300);
        printf("[*] Kernel result: 0x%08lx\n", (ULONG)vReq->Result);
        if (vReq->Result == 0) {
            ctx->lastControlAreaPtr = vReq->ControlAreaPtr;
            if (ctx->lastControlAreaPtr)
                printf("[+] ControlArea: 0x%llx  (use 'V' to map into another process)\n",
                       ctx->lastControlAreaPtr);
            RtlZeroMemory(ctx->VADArray,         VAD_SECTION_SIZE);
            RtlZeroMemory(ctx->VADArrayFileName, VAD_FILENAME_SEC_SIZE);
            if (SetEvent(ctx->hEventUSERMODEREADY))
                printf("[*] Tree refresh triggered\n");
        }
    } else {
        printf("[-] Failed to signal VAD insert event: %lu\n", GetLastError());
    }
}

// ─────────────────────────────────────────────────────────────────
// 'D' — remove a VAD node
// ─────────────────────────────────────────────────────────────────
void CmdDDelete(CmdContext* ctx)
{
    unsigned long long removeVpn = 0;

    if (ctx->treeCount > 0) {
        printf("Select node index (0-%zu) or Enter for manual VPN: ", ctx->treeCount - 1);
        fflush(stdout);
        memset(ctx->inputBuffer, 0, sizeof(ctx->inputBuffer));
        ctx->inputIndex = 0;
        while ((ctx->inputChar = _getch()) != '\r' && ctx->inputChar != '\n') {
            if (ctx->inputChar == '\b' && ctx->inputIndex > 0)
                { ctx->inputBuffer[--ctx->inputIndex] = 0; printf("\b \b"); }
            else if (isdigit(ctx->inputChar) && ctx->inputIndex < (int)sizeof(ctx->inputBuffer)-1)
                { ctx->inputBuffer[ctx->inputIndex++] = (char)ctx->inputChar; printf("%c", ctx->inputChar); }
        }
        printf("\n"); ctx->inputBuffer[ctx->inputIndex] = 0;
        if (ctx->inputIndex > 0) {
            size_t idx = (size_t)strtoull(ctx->inputBuffer, NULL, 10);
            if (idx < ctx->treeCount) {
                removeVpn = ctx->treeVpns[idx];
                printf("[*] Node #%zu: VPN 0x%llx\n", idx, removeVpn);
            } else { printf("[-] Index out of range\n"); return; }
        }
    }

    if (removeVpn == 0) {
        ReadHex(ctx, "Enter StartingVpn (hex): 0x");
        if (!ctx->inputIndex) { printf("[-] No VPN\n"); return; }
        removeVpn = strtoull(ctx->inputBuffer, NULL, 16);
    }

    printf("Free pool after unlink? (Y/N): "); fflush(stdout);
    int fc = _getch(); printf("%c\n", fc);

    PVAD_MODIFY_REQUEST r = (PVAD_MODIFY_REQUEST)ctx->VadModifyArray;
    memset(r, 0, sizeof(VAD_MODIFY_REQUEST));
    memcpy(r->identifier, "VREM", 4);
    r->StartingVpn  = removeVpn;
    r->FreeOnRemove = (fc == 'Y' || fc == 'y') ? TRUE : FALSE;
    r->isValid      = TRUE;

    if (SetEvent(ctx->hEventVAD_REMOVE)) {
        printf("[*] Sent remove request for VPN 0x%llx\n", removeVpn);
        Sleep(300);
        printf("[*] Kernel result: 0x%08lx\n", (ULONG)r->Result);
    } else {
        printf("[-] Failed to signal VAD remove event: %lu\n", GetLastError());
    }
}

// ─────────────────────────────────────────────────────────────────
// 'V' — map existing CA into another process
// ─────────────────────────────────────────────────────────────────
void CmdVMapView(CmdContext* ctx)
{
    printf("[*] Map Existing Section View into another process\n");
    printf("[*] Last ControlArea: 0x%llx\n", ctx->lastControlAreaPtr);
    ReadHex(ctx, "ControlArea ptr (hex, blank = use last): 0x");
    unsigned long long vCA = ctx->inputIndex > 0
        ? strtoull(ctx->inputBuffer, NULL, 16)
        : ctx->lastControlAreaPtr;
    if (!vCA) { printf("[-] No ControlArea ptr\n"); return; }

    printf("    [S] Source process (%s)\n",
        ctx->sourceProcess && ctx->sourceProcess[0] ? ctx->sourceProcess : "not set");
    printf("    [T] Target process (%s)\n",
        ctx->targetProcess && ctx->targetProcess[0] ? ctx->targetProcess : "not set");
    printf("    Map into [S/T]: "); fflush(stdout);
    int vc = _getch(); printf("%c\n", vc);
    bool vUseSource = (vc == 's' || vc == 'S');
    const char* vProc = vUseSource ? ctx->sourceProcess : ctx->targetProcess;
    if (!vProc || !vProc[0]) { printf("[-] Process not set\n"); return; }

    // QHNT for hint
    {
        PVAD_MODIFY_REQUEST q = (PVAD_MODIFY_REQUEST)ctx->VadModifyArray;
        memset(q, 0, sizeof(VAD_MODIFY_REQUEST));
        memcpy(q->identifier, "QHNT", 4);
        q->isValid = TRUE;
        UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, vProc,
                       (unsigned long long)ctx->sourceVA, 0, 0);
        if (SetEvent(ctx->hEventINIT)) Sleep(100);
        if (SetEvent(ctx->hEventVAD_INSERT)) {
            Sleep(300);
            if (q->SuggestedUserVpn)
                printf("[+] Suggested user VPN: 0x%016llx\n", q->SuggestedUserVpn);
            if (q->SuggestedKernelVpn)
                printf("[+] Suggested kernel VPN: 0x%016llx\n", q->SuggestedKernelVpn);
        }
    }

    ReadHex(ctx, "Enter VPN (hex): 0x");
    if (!ctx->inputIndex) { printf("[-] No VPN\n"); return; }
    unsigned long long vVPN = strtoull(ctx->inputBuffer, NULL, 16);

    ReadDec(ctx, "Enter region size in pages (decimal): ");
    unsigned long long vPages = (ctx->inputIndex > 0) ? strtoull(ctx->inputBuffer, NULL, 10) : 1;
    if (vPages == 0) vPages = 1;

    ULONG vProt = 0x04;
    ULONG vFlags = 0;
    if (g_MmVadFlags.valid) {
        const BITFIELD_MEMBER* mP = FindBitfieldMember(
            g_MmVadFlags.members, g_MmVadFlags.count, "Protection");
        if (mP) vFlags |= (vProt & ((1u << mP->bitLen) - 1u)) << mP->bitPos;
    } else {
        vFlags = (vProt & 0x1F) << 7;
    }

    UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, vProc,
                   (unsigned long long)ctx->sourceVA, vVPN, 0);
    if (SetEvent(ctx->hEventINIT))
        printf("[*] Process context updated to '%s'\n", vProc);

    PVAD_MODIFY_REQUEST vReq = (PVAD_MODIFY_REQUEST)ctx->VadModifyArray;
    memset(vReq, 0, sizeof(VAD_MODIFY_REQUEST));
    memcpy(vReq->identifier, "VINS", 4);
    vReq->StartingVpn = vVPN;
    vReq->EndingVpn   = vVPN + vPages - 1;
    vReq->Protection  = vProt;
    vReq->VadTypeRaw  = vFlags;
    vReq->NodeSize    = 0x88;
    vReq->SkipCharges = FALSE;
    vReq->ReuseCA     = vCA;
    vReq->isValid     = TRUE;

    printf("[*] Mapping CA=0x%llx into '%s'  VPN 0x%llx-0x%llx (%llu page(s))\n",
           vCA, vProc, vVPN, vVPN + vPages - 1, vPages);

    if (SetEvent(ctx->hEventVAD_INSERT)) {
        Sleep(300);
        printf("[*] Kernel result: 0x%08lx\n", (ULONG)vReq->Result);
        if (vReq->Result == 0) {
            printf("[+] Success\n");
            RtlZeroMemory(ctx->VADArray,         VAD_SECTION_SIZE);
            RtlZeroMemory(ctx->VADArrayFileName, VAD_FILENAME_SEC_SIZE);
            if (SetEvent(ctx->hEventUSERMODEREADY))
                printf("[*] Tree refresh triggered\n");
        }
    } else {
        printf("[-] Failed to signal VAD insert event: %lu\n", GetLastError());
    }
}

// -----------------------------------------------------------------
// CmdFFind — 'F': find all processes sharing a section/file view
// -----------------------------------------------------------------
void CmdFFind(CmdContext* ctx)
{
    PVAD_NODE      nodes  = (PVAD_NODE)ctx->VADArray;
    PVAD_NODE_FILE fnames = (PVAD_NODE_FILE)ctx->VADArrayFileName;
    size_t maxN  = VAD_SECTION_SIZE      / sizeof(VAD_NODE);
    size_t maxFN = VAD_FILENAME_SEC_SIZE / sizeof(VAD_NODE_FILE);
    int    total = 0, idx = 0, sel, cnt;
    size_t i;
    ULONG64    targetCA = 0;
    IpcCtx     ipc      = {};
    SFND_RESULT* res;
    char hdr[BOX_W] = {};

    for (i = 0; i < maxN; i++)
        if (nodes[i].Level) total++;

    if (!total) { printf("[-] VAD tree empty. Run '1' first.\n"); return; }

    printf("\n  #    Lvl  StartVpn       EndVpn         [v]  Type / FileName\n");
    for (i = 0; i < maxN; i++) {
        const char* fn;
        char typeTag[48] = "";
        if (!nodes[i].Level) continue;
        fn = (nodes[i].FileOffset && nodes[i].FileOffset < maxFN)
             ? (fnames[nodes[i].FileOffset].DevPath[0]
                ? fnames[nodes[i].FileOffset].DevPath
                : fnames[nodes[i].FileOffset].FileName)
             : "-";
        if (nodes[i].ControlAreaPtr) {
            if (g_MmSectionFlags.valid)
                BuildVadTypeTag(nodes[i].VadFlagsRaw, nodes[i].ControlAreaFlags,
                                nodes[i].IsVadShort, nodes[i].MappedViews,
                                nodes[i].SectionReferences, typeTag, sizeof(typeTag));
            printf("  %-4d %-4d 0x%013llx  0x%013llx  %-20s  %s\n", ++idx,
                   nodes[i].Level, nodes[i].StartingVpn, nodes[i].EndingVpn,
                   typeTag, fn);
        } else {
            printf("  %-4s %-4d 0x%013llx  0x%013llx  Private\n", "-",
                   nodes[i].Level, nodes[i].StartingVpn, nodes[i].EndingVpn);
        }
    }

    if (!idx) { printf("[-] No section nodes in tree.\n"); return; }
    printf("Select node [1-%d]: ", idx); fflush(stdout);
    memset(ctx->inputBuffer, 0, sizeof(ctx->inputBuffer));
    ctx->inputIndex = 0;
    while ((ctx->inputChar = _getch()) != '\r' && ctx->inputChar != '\n') {
        if (ctx->inputChar == '\b' && ctx->inputIndex > 0)
            { ctx->inputBuffer[--ctx->inputIndex] = 0; printf("\b \b"); }
        else if (isdigit(ctx->inputChar) && ctx->inputIndex < (int)sizeof(ctx->inputBuffer)-1)
            { ctx->inputBuffer[ctx->inputIndex++] = (char)ctx->inputChar; printf("%c", ctx->inputChar); }
    }
    printf("\n");
    sel = atoi(ctx->inputBuffer);
    if (sel < 1 || sel > idx) { printf("[-] Invalid selection\n"); return; }

    cnt = 0;
    for (i = 0; i < maxN; i++) {
        if (!nodes[i].Level || !nodes[i].ControlAreaPtr) continue;
        if (++cnt == sel) { targetCA = nodes[i].ControlAreaPtr; break; }
    }
    printf("[*] Searching CA=0x%llx across all processes...\n", targetCA);
    fflush(stdout);

    ipc.hEventVAD_INSERT = ctx->hEventVAD_INSERT;
    ipc.VadModifyArray   = ctx->VadModifyArray;

    res = (SFND_RESULT*)malloc(sizeof(SFND_RESULT));
    if (!res) { printf("[-] Out of memory\n"); return; }

    if (!Ipc_FindSectionViewers(&ipc, targetCA, res)) { free(res); return; }
    if (res->Result != 0) {
        printf("[-] SFND failed: 0x%08lX\n", (ULONG)res->Result);
        free(res); return;
    }

    BoxTop("Section Viewers");
    snprintf(hdr, sizeof(hdr), "  CA=0x%llx   %lu match(es)", targetCA, res->Count);
    BoxRow(hdr);
    BoxMid();

    if (res->Count == 0) {
        BoxRow("  (none found)");
    } else {
        BoxRow("  PID    Process          Protection             StartVpn       EndVpn         Name");
        BoxMid();
        for (ULONG j = 0; j < res->Count && j < SFND_MAX_ENTRIES; j++) {
            SFND_ENTRY* e = &res->Entries[j];
            // Choose best available name: ObjName > FileName > <anonymous>
            const char* name = e->HasObjName  ? e->ObjName  :
                               e->HasFileName ? e->FileName : "<anonymous>";
            const char* noObjMark = (!e->HasObjName && !e->HasFileName) ? "  [!no name]" : "";
            // Format protection the same way GetSymOffsets does
            static const char* protNames[] = {
                "PAGE_NOACCESS","PAGE_READONLY","PAGE_EXECUTE","PAGE_EXECUTE_READ",
                "PAGE_READWRITE","PAGE_WRITECOPY","PAGE_EXECUTE_READWRITE","PAGE_EXECUTE_WRITECOPY"
            };
            const char* protStr = (e->Protection < 8) ? protNames[e->Protection] : "UNKNOWN";
            char row[BOX_W * 2] = {};
            snprintf(row, sizeof(row), "  %-6lu %-16s %-22s 0x%013llx  0x%013llx  %s%s",
                     (ULONG)e->Pid, e->ImageName, protStr,
                     e->StartingVpn, e->EndingVpn,
                     name, noObjMark);
            BoxRow(row);
        }
    }
    BoxBot();
    free(res);
}
