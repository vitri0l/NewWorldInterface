#include "Commands.h"
#include <conio.h>
#include <cctype>
#include <vector>

// ─────────────────────────────────────────────────────────────────
// Pattern scan helpers
// ─────────────────────────────────────────────────────────────────
static bool ParseHexPattern(const char* hex, std::vector<unsigned char>& pat, std::vector<bool>& mask) {
    pat.clear(); mask.clear();
    if (!hex || !*hex) return false;
    for (const char* p = hex; *p; ) {
        if (isspace(*p)) { p++; continue; }
        if (*p == '?') {
            pat.push_back(0); mask.push_back(false);
            p++; if (*p == '?') p++;
        } else if (isxdigit(p[0]) && isxdigit(p[1])) {
            char b[3] = {p[0],p[1],0};
            pat.push_back((unsigned char)strtoul(b, nullptr, 16));
            mask.push_back(true); p += 2;
        } else { return false; }
    }
    return !pat.empty();
}

static bool ScanAndPrint(const void* addr, const char* hex) {
    std::vector<unsigned char> pat; std::vector<bool> mask;
    if (!ParseHexPattern(hex, pat, mask)) { printf("[-] Bad pattern\n"); return false; }
    const unsigned char* mem = (const unsigned char*)addr;
    bool found = false;
    for (size_t i = 0; i + pat.size() <= 4096; i++) {
        bool ok = true;
        for (size_t j = 0; j < pat.size(); j++)
            if (mask[j] && mem[i+j] != pat[j]) { ok = false; break; }
        if (ok) {
            printf("[+] Match at 0x%04zx\n", i);
            found = true;
        }
    }
    return found;
}

// SEH helpers
static BOOL EditMemorySafe(unsigned char* base, unsigned int off,
                            const unsigned char* nb, size_t n)
{
    __try {
        printf("Before [0x%X]:", off);
        for (size_t i=0;i<n;i++) printf(" %02X", base[i]);
        printf("\n");
        for (size_t i=0;i<n;i++) base[i]=nb[i];
        printf("After  [0x%X]:", off);
        for (size_t i=0;i<n;i++) printf(" %02X", base[i]);
        printf("\n");
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

static BOOL ReadMemorySafe(const unsigned char* ptr, size_t n)
{
    __try {
        for (size_t i=0;i<n;i+=16) {
            printf("  %04zX  ", i);
            size_t row = (n-i<16)?n-i:16;
            for (size_t j=0;j<row;j++) printf("%02X ",ptr[i+j]);
            for (size_t j=row;j<16;j++) printf("   ");
            printf(" | ");
            for (size_t j=0;j<row;j++) {
                unsigned char c=ptr[i+j];
                printf("%c",(c>=32&&c<=126)?c:'.');
            }
            printf("\n");
        }
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

// ─────────────────────────────────────────────────────────────────
// 'E' — edit memory
// ─────────────────────────────────────────────────────────────────
void CmdEEdit(CmdContext* ctx)
{
    printf("[*] Edit memory\n");
    printf("    [S] Source  [T] Target  Context [S/T]: "); fflush(stdout);
    int ec = _getch(); printf("%c\n", ec);
    bool es = (ec=='s'||ec=='S');
    const char* eProc = es ? ctx->sourceProcess : ctx->targetProcess;
    if (!eProc || !eProc[0]) { printf("[-] Process not set\n"); return; }

    printf("    [V] VPN  [A] Full VA  [default=V]: "); fflush(stdout);
    int et = _getch(); printf("%c\n", et);
    bool isVPN = !(et=='a'||et=='A');

    printf("Enter %s (hex): 0x", isVPN?"VPN":"VA"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    if(!ctx->inputIndex){printf("[-] No address\n");return;}
    unsigned long long raw = strtoull(ctx->inputBuffer,NULL,16);
    PVOID base = isVPN ? (PVOID)(raw*0x1000ULL) : (PVOID)(raw&~0xFFFULL);

    printf("Enter page offset (hex 000-FFF): 0x"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    unsigned int off = ctx->inputIndex>0 ? (unsigned int)(strtoull(ctx->inputBuffer,NULL,16)&0xFFF) : 0;

    std::vector<unsigned char> bytes;
    bool inNum=false; int tIdx=0; char tmp[3]={};
    printf("Bytes to write (hex space-sep): "); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'){if(ctx->inputIndex>0){ctx->inputIndex--;ctx->inputBuffer[ctx->inputIndex]=0;printf("\b \b");if(inNum&&tIdx>0){tmp[--tIdx]=0;if(!tIdx)inNum=false;}}}
        else if(ctx->inputChar==' '){if(tIdx>0){bytes.push_back((unsigned char)strtoul(tmp,NULL,16));memset(tmp,0,3);tIdx=0;inNum=false;}}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){
            ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);
            if(tIdx<2){tmp[tIdx++]=(char)ctx->inputChar;inNum=true;}
            else{bytes.push_back((unsigned char)strtoul(tmp,NULL,16));memset(tmp,0,3);tmp[0]=(char)ctx->inputChar;tIdx=1;}
        }
    }
    if(inNum&&tIdx>0) bytes.push_back((unsigned char)strtoul(tmp,NULL,16));
    printf("\n");
    if(bytes.empty()){printf("[-] No bytes\n");return;}

    size_t cnt = bytes.size();
    if(off+cnt>4096){printf("[!] Truncating to page boundary\n");cnt=4096-off;}
    unsigned char* ptr = (unsigned char*)base + off;
    if(EditMemorySafe(ptr,off,bytes.data(),cnt))
        printf("[+] Wrote %zu byte(s) to %s VA 0x%p+0x%X\n",cnt,eProc,base,off);
    else
        printf("[-] Access violation at 0x%p+0x%X\n",base,off);
}

// ─────────────────────────────────────────────────────────────────
// 'Q' — read memory
// ─────────────────────────────────────────────────────────────────
void CmdQRead(CmdContext* ctx)
{
    printf("[*] Read memory\n");
    printf("    [S] Source  [T] Target  Context [S/T]: "); fflush(stdout);
    int qc = _getch(); printf("%c\n", qc);
    bool qs = (qc=='s'||qc=='S');
    const char* qProc = qs ? ctx->sourceProcess : ctx->targetProcess;
    if (!qProc||!qProc[0]){printf("[-] Process not set\n");return;}

    printf("    [V] VPN  [A] Full VA  [default=V]: "); fflush(stdout);
    int qt = _getch(); printf("%c\n", qt);
    bool qIsVPN = !(qt=='a'||qt=='A');

    printf("Enter %s (hex): 0x", qIsVPN?"VPN":"VA"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    if(!ctx->inputIndex){printf("[-] No address\n");return;}
    unsigned long long raw = strtoull(ctx->inputBuffer,NULL,16);
    PVOID base = qIsVPN ? (PVOID)(raw*0x1000ULL) : (PVOID)(raw&~0xFFFULL);

    printf("Enter page offset (hex 000-FFF): 0x"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    unsigned int off = ctx->inputIndex>0 ? (unsigned int)(strtoull(ctx->inputBuffer,NULL,16)&0xFFF) : 0;

    printf("Bytes to read (decimal) [16]: "); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    size_t cnt = ctx->inputIndex>0 ? (size_t)strtoull(ctx->inputBuffer,NULL,10) : 16;
    if(!cnt) cnt=16;
    if(off+cnt>4096){printf("[!] Clamping to page boundary\n");cnt=4096-off;}

    const unsigned char* ptr = (const unsigned char*)base + off;
    if(!ReadMemorySafe(ptr,cnt))
        printf("[-] Access violation at 0x%p+0x%X\n",base,off);
}

// ─────────────────────────────────────────────────────────────────
// '4' — link PTE
// ─────────────────────────────────────────────────────────────────
void Cmd4Link(CmdContext* ctx)
{
    if (!ctx->sourceProcess || !ctx->sourceProcess[0]) { printf("[-] Source process not set (I)\n"); return; }
    if (!ctx->targetProcess || !ctx->targetProcess[0]) { printf("[-] Target process not set (O)\n"); return; }

    PVAD_NODE      nodes  = (PVAD_NODE)ctx->VADArray;
    PVAD_NODE_FILE fnames = (PVAD_NODE_FILE)ctx->VADArrayFileName;
    size_t maxN  = VAD_SECTION_SIZE      / sizeof(VAD_NODE);
    size_t maxFN = VAD_FILENAME_SEC_SIZE / sizeof(VAD_NODE_FILE);

    // ── Target VA: show target VAD tree and let user pick ────────
    printf("[*] Populating target VAD for '%s'...\n", ctx->targetProcess);
    RtlZeroMemory(ctx->VADArray,         VAD_SECTION_SIZE);
    RtlZeroMemory(ctx->VADArrayFileName, VAD_FILENAME_SEC_SIZE);
    ((PINIT)ctx->SymbolsArray)->walkMode = 0; // target
    if (SetEvent(ctx->hEventUSERMODEREADY)) Sleep(600);

    printf("[*] Target VAD nodes:\n");
    printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
        "#", "VADNode", "StartingVpn", "EndingVpn", "4KBs", "Protection", "Type", "FileName");
    printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
        "-----", "-----------------", "-------------", "-------------", "---------",
        "--------------------------", "--------------", "-----------------------------------");
    int idx = 0;
    for (size_t i = 0; i < maxN; i++) {
        if (!nodes[i].Level || (nodes[i].Level == -1 && nodes[i].StartingVpn == 0xFFFFFFFFFFFFFFFEULL)) continue;
        const char* fn = (nodes[i].FileOffset && nodes[i].FileOffset < maxFN)
            ? (fnames[nodes[i].FileOffset].DevPath[0]
               ? fnames[nodes[i].FileOffset].DevPath
               : fnames[nodes[i].FileOffset].FileName)
            : "-";
        char typeTag[48] = "";
        if (g_MmSectionFlags.valid)
            BuildVadTypeTag(nodes[i].VadFlagsRaw, nodes[i].ControlAreaFlags, nodes[i].IsVadShort,
                nodes[i].MappedViews, nodes[i].SectionReferences, typeTag, sizeof(typeTag));
        char protBuf[40];
        snprintf(protBuf, sizeof(protBuf), "%-22s [0x%x]",
            ProtectionToStr((PROTECTION)nodes[i].Protection), nodes[i].Protection);
        printf("%-5d  0x%-16p  0x%011llx  0x%011llx  %-9llu  %-26s  %-14s  %-35s\n",
            ++idx,
            nodes[i].VADNode,
            nodes[i].StartingVpn,
            nodes[i].EndingVpn,
            nodes[i].EndingVpn - nodes[i].StartingVpn + 1,
            protBuf, typeTag, fn);
    }
    printf("\n");
    if (!idx) { printf("[-] No target VAD nodes found\n"); return; }

    printf("Select target node [1-%d]: ", idx); fflush(stdout);
    memset(ctx->inputBuffer, 0, sizeof(ctx->inputBuffer)); ctx->inputIndex = 0;
    while ((ctx->inputChar = _getch()) != '\r' && ctx->inputChar != '\n') {
        if (ctx->inputChar == '\b' && ctx->inputIndex > 0) { ctx->inputBuffer[--ctx->inputIndex] = 0; printf("\b \b"); }
        else if (isdigit(ctx->inputChar) && ctx->inputIndex < (int)sizeof(ctx->inputBuffer)-1)
            { ctx->inputBuffer[ctx->inputIndex++] = (char)ctx->inputChar; printf("%c", ctx->inputChar); }
    }
    printf("\n");
    int selTgt = atoi(ctx->inputBuffer);
    if (selTgt < 1 || selTgt > idx) { printf("[-] Invalid selection\n"); return; }

    int cnt = 0;
    for (size_t i = 0; i < maxN; i++) {
        if (!nodes[i].Level) continue;
        if (++cnt == selTgt) { ctx->targetVPN = nodes[i].StartingVpn; break; }
    }
    printf("[+] Target VPN: 0x%llx  (VA 0x%llx)\n", ctx->targetVPN, ctx->targetVPN << 12);

    // ── Source VA: derive free VPN hint directly from the source VAD array ──
    // Populate the source VAD tree, then scan it locally — no QHNT IPC needed.
    printf("[*] Populating source VAD for '%s'...\n", ctx->sourceProcess);
    RtlZeroMemory(ctx->VADArray,         VAD_SECTION_SIZE);
    RtlZeroMemory(ctx->VADArrayFileName, VAD_FILENAME_SEC_SIZE);
    ((PINIT)ctx->SymbolsArray)->walkMode = 1; // source
    UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, ctx->targetProcess, 0, 0, 0);
    SetEvent(ctx->hEventINIT);
    Sleep(200);
    if (SetEvent(ctx->hEventUSERMODEREADY)) Sleep(600);

    // Find the highest EndingVpn in user space (< 0x400000000) and add 1.
    unsigned long long maxEndVpn = 0;
    for (size_t i = 0; i < maxN; i++) {
        if (!nodes[i].Level || (nodes[i].Level == -1 && nodes[i].StartingVpn == 0xFFFFFFFFFFFFFFFEULL))
            continue;
        if (nodes[i].EndingVpn < 0x400000000ULL && nodes[i].EndingVpn > maxEndVpn)
            maxEndVpn = nodes[i].EndingVpn;
    }

    if (!maxEndVpn) { printf("[-] Could not determine free VPN from source VAD tree\n"); return; }

    unsigned long long hintVPN = maxEndVpn + 1;
    unsigned long long srcVA   = hintVPN << 12;
    ctx->sourceVA = (PVOID)srcVA;
    printf("[+] Source VA (free hint): 0x%llx  (VPN 0x%llx)\n", srcVA, hintVPN);

    UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, ctx->targetProcess,
                   (unsigned long long)ctx->sourceVA, ctx->targetVPN, 0);
    if (SetEvent(ctx->hEventINIT)) printf("[*] INIT sent\n");
    if (SetEvent(ctx->hEventLINK)) printf("[*] Link event sent\n");
    else                           printf("[-] Link event failed: %lu\n", GetLastError());
}

// ─────────────────────────────────────────────────────────────────
// 'A' — change memory protection
// ─────────────────────────────────────────────────────────────────
void CmdAProtect(CmdContext* ctx)
{
    printf("[*] Change memory protection\n");
    printf("    [S] Source  [T] Target  Context [S/T]: "); fflush(stdout);
    int ac = _getch(); printf("%c\n", ac);
    bool as = (ac=='s'||ac=='S');
    const char* aProc = as ? ctx->sourceProcess : ctx->targetProcess;
    if(!aProc||!aProc[0]){printf("[-] Process not set\n");return;}

    printf("Enter VA (hex): 0x"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    if(!ctx->inputIndex){printf("[-] No VA\n");return;}
    PVOID aVA = (PVOID)strtoull(ctx->inputBuffer,NULL,16);

    printf("1=RO 2=X 3=RX 4=RW 5=NA 6=RWX: "); fflush(stdout);
    int pc = _getch()-'0'; printf("%d\n", pc);
    ULONG np=0; const char* pn="";
    switch(pc){
    case 1: np=PAGE_READONLY;          pn="PAGE_READONLY";          break;
    case 2: np=PAGE_EXECUTE;           pn="PAGE_EXECUTE";           break;
    case 3: np=PAGE_EXECUTE_READ;      pn="PAGE_EXECUTE_READ";      break;
    case 4: np=PAGE_READWRITE;         pn="PAGE_READWRITE";         break;
    case 5: np=PAGE_NOACCESS;          pn="PAGE_NOACCESS";          break;
    case 6: np=PAGE_EXECUTE_READWRITE; pn="PAGE_EXECUTE_READWRITE"; break;
    default: printf("[-] Invalid\n"); return;
    }
    UpdateInitData(ctx->SymbolsArray, aProc,
                   as ? ctx->targetProcess : ctx->sourceProcess,
                   (unsigned long long)aVA, ctx->targetVPN, np);
    if(SetEvent(ctx->hEventINIT))
        printf("[*] Protection change sent (%s on %s VA 0x%p)\n",pn,aProc,aVA);
    else
        printf("[-] SetEvent failed: %lu\n",GetLastError());
}

// ─────────────────────────────────────────────────────────────────
// 'W' — write physical memory
// ─────────────────────────────────────────────────────────────────
void CmdWWritePhys(CmdContext* ctx)
{
    printf("[*] Write Physical Memory\n");
    printf("    [S] Source  [T] Target  Context [S/T]: "); fflush(stdout);
    int wc = _getch(); printf("%c\n", wc);
    bool ws = (wc=='s'||wc=='S');
    const char* wProc = ws ? ctx->sourceProcess : ctx->targetProcess;
    if(!wProc||!wProc[0]){printf("[-] Process not set\n");return;}

    printf("Enter target VA (hex): 0x"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    if(!ctx->inputIndex){printf("[-] No VA\n");return;}
    PVOID va = (PVOID)strtoull(ctx->inputBuffer,NULL,16);

    printf("Page offset (hex 000-FFF): 0x"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    ULONG off = ctx->inputIndex>0 ? (ULONG)strtoul(ctx->inputBuffer,NULL,16) : 0;
    if(off>=4096){printf("[-] Offset out of range\n");return;}

    std::vector<unsigned char> bytes;
    bool inNum=false; int ti=0; char tmp[3]={};
    printf("Bytes (hex space-sep): "); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'){if(ctx->inputIndex>0){ctx->inputIndex--;ctx->inputBuffer[ctx->inputIndex]=0;printf("\b \b");if(inNum&&ti>0){tmp[--ti]=0;if(!ti)inNum=false;}}}
        else if(ctx->inputChar==' '){if(ti>0){bytes.push_back((unsigned char)strtoul(tmp,NULL,16));memset(tmp,0,3);ti=0;inNum=false;}}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){
            ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);
            if(ti<2){tmp[ti++]=(char)ctx->inputChar;inNum=true;}
            else{bytes.push_back((unsigned char)strtoul(tmp,NULL,16));memset(tmp,0,3);tmp[0]=(char)ctx->inputChar;ti=1;}
        }
    }
    if(inNum&&ti>0) bytes.push_back((unsigned char)strtoul(tmp,NULL,16));
    printf("\n");
    if(bytes.empty()){printf("[-] No bytes\n");return;}

    size_t sz = bytes.size();
    if(off+sz>4096) sz=4096-off;
    if(sz>MAX_WRITE_BUFFER_SIZE) sz=MAX_WRITE_BUFFER_SIZE;

    PWRITE_PHYS_REQUEST req = (PWRITE_PHYS_REQUEST)ctx->WritePhysArray;
    memset(req,0,sizeof(WRITE_PHYS_REQUEST));
    memcpy(req->identifier,"WPHY",4);
    req->targetVirtualAddress = (unsigned long long)va * 0x1000;
    req->offsetInPage = off;
    req->dataSize = (ULONG)sz;
    for(size_t i=0;i<sz;i++) req->data[i]=bytes[i];
    req->isValid = TRUE;

    if(SetEvent(ctx->hEventWRITE_PHYS))
        printf("[+] Write request sent (VA=0x%p off=0x%lX size=%zu)\n",va,off,sz);
    else
        printf("[-] SetEvent failed: %lu\n",GetLastError());
}

// ─────────────────────────────────────────────────────────────────
// 'R' — read physical memory
// ─────────────────────────────────────────────────────────────────
void CmdRReadPhys(CmdContext* ctx)
{
    printf("[*] Read Physical Memory\n");
    printf("    [S] Source  [T] Target  Context [S/T]: "); fflush(stdout);
    int rc = _getch(); printf("%c\n", rc);
    bool rs = (rc=='s'||rc=='S');
    const char* rProc = rs ? ctx->sourceProcess : ctx->targetProcess;
    if(!rProc||!rProc[0]){printf("[-] Process not set\n");return;}

    printf("Enter VPN (hex): 0x"); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isxdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    if(!ctx->inputIndex){printf("[-] No VPN\n");return;}
    unsigned long long rVPN = strtoull(ctx->inputBuffer,NULL,16);

    unsigned long long rVadPages = 1;
    {
        PVAD_NODE nodes = (PVAD_NODE)ctx->VADArray;
        size_t maxN = VAD_SECTION_SIZE/sizeof(VAD_NODE);
        for(size_t i=0;i<maxN;i++){
            if(!nodes[i].Level) continue;
            if(nodes[i].StartingVpn<=rVPN && rVPN<=nodes[i].EndingVpn){
                rVadPages = nodes[i].EndingVpn - rVPN + 1;
                printf("[*] VAD: StartVpn=0x%llx EndVpn=0x%llx (%llu page(s))\n",
                       nodes[i].StartingVpn, nodes[i].EndingVpn, rVadPages);
                break;
            }
        }
    }

    printf("Pages to dump [1-%llu, default=all]: ", rVadPages); fflush(stdout);
    memset(ctx->inputBuffer,0,sizeof(ctx->inputBuffer)); ctx->inputIndex=0;
    while((ctx->inputChar=_getch())!='\r'&&ctx->inputChar!='\n'){
        if(ctx->inputChar=='\b'&&ctx->inputIndex>0){ctx->inputBuffer[--ctx->inputIndex]=0;printf("\b \b");}
        else if(isdigit(ctx->inputChar)&&ctx->inputIndex<(int)sizeof(ctx->inputBuffer)-1){ctx->inputBuffer[ctx->inputIndex++]=(char)ctx->inputChar;printf("%c",ctx->inputChar);}
    }
    printf("\n"); ctx->inputBuffer[ctx->inputIndex]=0;
    unsigned long long dumpPgs = ctx->inputIndex>0 ? strtoull(ctx->inputBuffer,NULL,10) : rVadPages;
    if(!dumpPgs) dumpPgs=1;
    if(dumpPgs>rVadPages) dumpPgs=rVadPages;

    UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, rProc,
                   (unsigned long long)ctx->sourceVA, rVPN, 0);
    if(SetEvent(ctx->hEventINIT)) printf("[*] Context updated\n");

    for(unsigned long long p=0;p<dumpPgs;p++){
        unsigned long long curVPN = rVPN+p;
        PVOID curVA = (PVOID)(curVPN*0x1000ULL);
        PREAD_PHYS_REQUEST req = (PREAD_PHYS_REQUEST)ctx->ReadPhysArray;
        memset(req,0,sizeof(READ_PHYS_REQUEST));
        memcpy(req->identifier,"RPHY",4);
        req->targetVirtualAddress = curVA;
        req->isValid = TRUE;
        printf("\n--- Page %llu/%llu  VPN=0x%llx  VA=0x%p ---\n",p+1,dumpPgs,curVPN,curVA);
        if(!SetEvent(ctx->hEventREAD_PHYS)){printf("[-] SetEvent failed\n");break;}
        DWORD w=0; while(req->isValid&&w<2000){Sleep(50);w+=50;}
        if(req->identifier[0]==0){
            const unsigned char* pd = req->pageData;
            for(size_t i=0;i<MAX_READ_BUFFER_SIZE;i+=16){
                printf("  %04zX  ",i);
                size_t row=(MAX_READ_BUFFER_SIZE-i<16)?MAX_READ_BUFFER_SIZE-i:16;
                for(size_t j=0;j<row;j++) printf("%02X ",pd[i+j]);
                for(size_t j=row;j<16;j++) printf("   ");
                printf(" | ");
                for(size_t j=0;j<row;j++){unsigned char c=pd[i+j];printf("%c",(c>=32&&c<=126)?c:'.');}
                printf("\n");
            }
        } else { printf("[-] Page %llu failed\n",p+1); break; }
    }
    printf("\n[+] Done — %llu page(s)\n",dumpPgs);
}

// ─────────────────────────────────────────────────────────────────
// 'P' — pattern scan
// ─────────────────────────────────────────────────────────────────
void CmdPScan(CmdContext* ctx)
{
    char pat[256]={};
    int pi=0;
    printf("Enter hex pattern (e.g. '90 90 ? ? FF'): "); fflush(stdout);
    int pc;
    while((pc=_getch())!='\r'&&pc!='\n'&&pi<255){
        if(pc=='\b'){if(pi>0){pat[--pi]=0;printf("\b \b");}}
        else if(isxdigit(pc)||pc=='?'||pc==' '){pat[pi++]=(char)pc;printf("%c",pc);}
    }
    printf("\n"); pat[pi]=0;
    if(!pi){printf("[-] No pattern\n");return;}
    if(!ctx->sourceVA){printf("[-] sourceVA not set\n");return;}

    PVAD_NODE nodes = (PVAD_NODE)ctx->VADArray;
    size_t maxN = VAD_SECTION_SIZE/sizeof(VAD_NODE);
    bool go = true;
    for(size_t i=0;i<maxN&&go;i++){
        if(!nodes[i].Level) continue;
        unsigned long long vpn = nodes[i].StartingVpn;
        unsigned long long pgs = nodes[i].EndingVpn - vpn + 1;
        for(unsigned long long pg=0;pg<pgs&&go;pg++){
            ctx->targetVPN = vpn+pg;
            UpdateInitData(ctx->SymbolsArray, ctx->sourceProcess, ctx->targetProcess,
                           (unsigned long long)ctx->sourceVA, ctx->targetVPN, 0);
            if(SetEvent(ctx->hEventLINK))
                printf("[*] Linked VPN 0x%llx\n", ctx->targetVPN);
            if(ScanAndPrint(ctx->sourceVA, pat)) go = false;
        }
    }
}
