#include "Commands.h"
#include <conio.h>
#include <cctype>

void Cmd1Walk(CmdContext* ctx)
{
    printf("[*] Walk: T=Target  S=Source  B=Both [T]: "); fflush(stdout);
    int wch = _getch(); printf("%c\n", wch);
    UCHAR wmode = (wch=='s'||wch=='S') ? 1 : (wch=='b'||wch=='B') ? 2 : 0;
    ((PINIT)ctx->SymbolsArray)->walkMode = wmode;

    RtlZeroMemory(ctx->VADArray,         VAD_SECTION_SIZE);
    RtlZeroMemory(ctx->VADArrayFileName, VAD_FILENAME_SEC_SIZE);

    BOOL canWalk = (wmode == 1)
        ? (ctx->sourceProcess && ctx->sourceProcess[0])
        : (ctx->targetProcess && ctx->targetProcess[0]);

    if (canWalk) {
        if (SetEvent(ctx->hEventUSERMODEREADY))
            printf("[*] Notified driver to populate VAD-Tree (mode=%s)\n",
                   wmode==0?"target":wmode==1?"source":"both");
        else
            printf("[-] Failed to notify driver: %lu\n", GetLastError());
    } else {
        printf("[-] Required process not configured — use 'I' or 'O'\n");
    }
}

void Cmd2Print(CmdContext* ctx)
{
    GetSymOffsets(ctx->VADArray, VAD_SECTION_SIZE,
                  ctx->VADArrayFileName, VAD_FILENAME_SEC_SIZE);
}

void CmdTTree(CmdContext* ctx)
{
    ctx->treeCount = ShowTree(ctx->VADArray, VAD_SECTION_SIZE,
                              ctx->VADArrayFileName, VAD_FILENAME_SEC_SIZE,
                              ctx->treeVpns, VAD_MAX_NODES);
    if (ctx->treeCount == 0)
        printf("[!] Tree is empty — run '1' first\n");
}

void CmdISource(CmdContext* ctx)
{
    RtlZeroMemory(ctx->sourceProcessBuf, sizeof(ctx->sourceProcessBuf));
    int idx = 0;
    printf("Enter source process name (max 15 chars): "); fflush(stdout);
    int c;
    while ((c = _getch()) != '\r' && c != '\n') {
        if (c == '\b') {
            if (idx > 0) { ctx->sourceProcessBuf[--idx] = 0; printf("\b \b"); }
        } else if (c >= 32 && c <= 126 && idx < 15) {
            ctx->sourceProcessBuf[idx++] = (char)c; printf("%c", c);
        }
    }
    ctx->sourceProcessBuf[idx] = 0; printf("\n");
    if (idx > 0) {
        ctx->sourceProcess = ctx->sourceProcessBuf;
        UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, ctx->targetProcess,
                       (unsigned long long)ctx->sourceVA, ctx->targetVPN, 0);
        if (SetEvent(ctx->hEventINIT))
            printf("[*] Source process set to: %s\n", ctx->sourceProcess);
    } else {
        printf("[*] No change\n");
    }
}

void CmdOTarget(CmdContext* ctx)
{
    RtlZeroMemory(ctx->targetProcessBuf, sizeof(ctx->targetProcessBuf));
    int idx = 0;
    printf("Enter target process name (max 15 chars): "); fflush(stdout);
    int c;
    while ((c = _getch()) != '\r' && c != '\n') {
        if (c == '\b') {
            if (idx > 0) { ctx->targetProcessBuf[--idx] = 0; printf("\b \b"); }
        } else if (c >= 32 && c <= 126 && idx < 15) {
            ctx->targetProcessBuf[idx++] = (char)c; printf("%c", c);
        }
    }
    ctx->targetProcessBuf[idx] = 0; printf("\n");
    if (idx > 0) {
        ctx->targetProcess = ctx->targetProcessBuf;
        UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, ctx->targetProcess,
                       (unsigned long long)ctx->sourceVA, ctx->targetVPN, 0);
        if (SetEvent(ctx->hEventINIT))
            printf("[*] Target process set to: %s\n", ctx->targetProcess);
    } else {
        printf("[*] No change\n");
    }
}
