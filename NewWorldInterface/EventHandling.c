#include <ntifs.h>
// ---
#include "EventHandling.h"


VOID WorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Event signaled\n");
		}
		else {
			DbgPrint("[-] WorkerThread Failed to wait for event: %08X\n", status);
		}
		g_StopRequested = TRUE;
		pEvent->Header.SignalState = 0; // Reset the event
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID LinkWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0; // Reset the event
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] LinkWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}
		// check if gInit.sourceProcess and gInit.targetProcess contains data or is filled with null-bytes
		if (gInit.sourceProcess[0] == '\0' || gInit.targetProcess[0] == '\0') {
			DbgPrint("[-] LinkWorkerThread: sourceProcess or targetProcess is invalid (empty)\n");
			continue; // keep thread alive
		}

		gSourceProcess = GetProcessByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		unsigned long long targetCR3 = GetDirectoryTableBaseByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
		unsigned long long sourceCR3 = GetDirectoryTableBaseByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
		if (gInit.targetVPN != 0x0) {
			PVOID targetVA = (PVOID)(gInit.targetVPN * 0x1000);
			DbgPrint("[+] LinkWorkerThread called\n");
			DbgPrint("    sourceVA:  0x%llx\n", gInit.sourceVA);
			DbgPrint("    targetCR3: 0x%llx\n", targetCR3);
			DbgPrint("    sourceCR3: 0x%llx\n", sourceCR3);

			// The source VA is a freshly computed free hint — no page table entry
			// exists for it yet.  Allocate and commit a page there so that Windows
			// creates the PTE before ChangeRef tries to walk to it.
			KAPC_STATE apc;
			KeStackAttachProcess(gSourceProcess, &apc);
			PVOID allocBase = (PVOID)gInit.sourceVA;
			SIZE_T allocSize = 0x1000;
			NTSTATUS allocStatus = ZwAllocateVirtualMemory(
				ZwCurrentProcess(), &allocBase, 0, &allocSize,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!NT_SUCCESS(allocStatus)) {
				DbgPrint("[-] LinkWorkerThread: ZwAllocateVirtualMemory failed %08X for sourceVA=0x%llx\n",
					allocStatus, gInit.sourceVA);
				KeUnstackDetachProcess(&apc);
				continue;
			}
			// Touch the page so the PTE is actually populated (demand-zero -> present)
			__try {
				*(volatile UCHAR*)allocBase = 0;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("[-] LinkWorkerThread: page touch faulted %08X\n", GetExceptionCode());
			}
			KeUnstackDetachProcess(&apc);
			DbgPrint("[+] LinkWorkerThread: committed sourceVA=0x%llx\n", gInit.sourceVA);

			ChangeRef(gInit.sourceVA, gSourceProcess, sourceCR3, (unsigned long long)targetVA, pTargetProcess, targetCR3);
		}
		else {
			DbgPrint("[-] LinkWorkerThread: targetVPN is invalid (0x0)\n");
			continue; // keep thread alive
		}
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID UnlinkWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0; // Reset the event
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UnlinkWorkerThread, Failed to wait for event: %08X\n", status);
			break;
		}
		if (gOrigVal != 0x0 && gOrigPhys.QuadPart != 0x0 && gSourceProcess != NULL) {
			KAPC_STATE ApcState; // must be KAPC_STATE (the struct), NOT PKAPC_STATE (a pointer)
			KeStackAttachProcess(gSourceProcess, &ApcState);
			PVOID temp = MmGetVirtualForPhysical(gOrigPhys);
			if (temp != NULL) {
				memcpy(temp, &gOrigVal, sizeof(gOrigVal));
				unsigned long long curVal = *(unsigned long long*)temp;
				if (curVal != 0x0) {
					if (curVal == gOrigVal) {
						DbgPrint("[+] Successfully restored all modified PTEs to their original values\n");
					}
					else {
						DbgPrint("[-] Failed to restore modified PTEs\n");
					}
				}
				else {
					DbgPrint("[-] MmGetVirtualForPhysical has no content\n");
				}
			} else {
				DbgPrint("[-] MmGetVirtualForPhysical returned NULL for phys=0x%llx\n",
					gOrigPhys.QuadPart);
			}
			KeUnstackDetachProcess(&ApcState);
		}
		else {
			DbgPrint("[-] No modified PTEs to restore\n");
		}

		// -------------------------------------------------------
		// Session reset — DO NOT close any kernel handles.
		// All named sections and events must remain open so a
		// restarted usermode can call OpenFileMappingW /
		// OpenEventW and reconnect without reloading the driver.
		// -------------------------------------------------------

		// Unmap the symbol-input view so INITWorkerThread remaps
		// it (and re-reads offsets) when the next INIT fires.
		if (pInSection != NULL) {
			ZwUnmapViewOfSection(ZwCurrentProcess(), pInSection);
			pInSection = NULL;
		}

		// Reset per-session state
		gSourceProcess      = NULL;
		gOrigVal            = 0x0;
		gOrigPhys.QuadPart  = 0;
		gSecVADIndex        = 0;
		gCurrFileNameOffset = 1;

		// Zero output buffers so stale data isn't shown on reconnect
		if (gSection)          RtlZeroMemory(gSection,          gViewSize);
		if (gFileNameSection)  RtlZeroMemory(gFileNameSection,  gFileNameViewSize);
		if (gVadModifySection) RtlZeroMemory(gVadModifySection, sizeof(VAD_MODIFY_REQUEST));

		// Zero INIT / symbol structs — will be repopulated on next INIT signal
		RtlZeroMemory(&gInit,    sizeof(gInit));
		RtlZeroMemory(&gSymInfo, sizeof(gSymInfo));

		DbgPrint("[+] UnlinkWorkerThread: session reset complete — driver ready for reconnect\n");
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID UserModeReadWorkerThread(PVOID Context) {
	// g_StopRequested is initialised to FALSE in DriverCore.c; do NOT reset it here —
	// DriverUnload may have already set it TRUE before this thread is scheduled.
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		// SynchronizationEvent: KeWaitForSingleObject atomically resets the event on wake.
		// Do NOT manually clear SignalState — that would discard any signal that arrived
		// while WalkVAD was running, causing subsequent '1' presses to appear to do nothing.
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UserModeReadWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}

		// Read walkMode directly from the live input section so a new mode written by '1'
		// is immediately honoured without requiring a new INIT event.
		UCHAR liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;

		// Verify the process required by the requested walk mode is configured
		if (liveWalkMode == 1) {
			if (gInit.sourceProcess[0] == '\0') {
				DbgPrint("[-] UserModeReadWorkerThread: sourceProcess not set (mode=source) — waiting\n");
				continue;
			}
		} else {
			if (gInit.targetProcess[0] == '\0') {
				DbgPrint("[-] UserModeReadWorkerThread: targetProcess not set — waiting\n");
				continue;
			}
		}

		// Make sure section is not getting paged-out | VAD Node Info - Memory Section
		DbgPrint("[+] Allocating MDL for section\n");
		gpDeviceContext->pMdl = IoAllocateMdl(gSection, gViewSize, FALSE, FALSE, NULL);

		DbgPrint("[+] Source Process: %s\n", gInit.sourceProcess);
		DbgPrint("[+] Target Process: %s\n", gInit.targetProcess);
		gSourceProcess = GetProcessByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);

		RtlZeroMemory(gFileNameSection, gFileNameViewSize);
		RtlZeroMemory(gSection, gViewSize);
		gSecVADIndex        = 0;
		gCurrFileNameOffset = 1;

		if (liveWalkMode == 1) {
				// Source process only
				if (gSourceProcess) {
					WalkVAD(gSourceProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: source walk done, %zu entries\n", gSecVADIndex);
				}
			} else if (liveWalkMode == 2) {
				// Target first
				if (pTargetProcess) {
					WalkVAD(pTargetProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: target walk done, %zu entries\n", gSecVADIndex);
				}
				// Sentinel: Level=-1, magic StartingVpn marks the boundary
				size_t maxSlots = gViewSize / sizeof(VAD_NODE);
				if (gSecVADIndex < maxSlots - 1) {
					PVAD_NODE sent = (PVAD_NODE)gSection + gSecVADIndex;
					RtlZeroMemory(sent, sizeof(VAD_NODE));
					sent->Level       = -1;
					sent->StartingVpn = 0xFFFFFFFFFFFFFFFEULL;
					gSecVADIndex++;
				}
				// Source second
				if (gSourceProcess) {
					WalkVAD(gSourceProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: source walk done, %zu total entries\n", gSecVADIndex);
				}
			} else {
				// Target only (mode 0, default)
				if (pTargetProcess) {
					WalkVAD(pTargetProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
						gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
						gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags, gSymInfo.FILEOBJECTFileName, 0x0);
					DbgPrint("[+] UserModeReadWorkerThread: target walk done, %zu entries\n", gSecVADIndex);
									}
								}
							}
					PsTerminateSystemThread(STATUS_SUCCESS);
				}

VOID INITWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	int test;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0; // Reset the event
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL); // TODO: perhaps change to WaitForMultipleObjects
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UserModeReadWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}
		if (pInSection == NULL) {
			status = ZwMapViewOfSection(hInSection, ZwCurrentProcess(), &pInSection,
				0, 0, NULL, &gSymsViewSize, ViewShare,
				0, PAGE_READONLY);
			if (!NT_SUCCESS(status)) {
				DbgPrint("[-] Failed to map view of input section: %08X\n", status);
				ZwClose(hInSection);
				IoDeleteSymbolicLink(&usSymbolicLinkName);
				IoDeleteDevice(gpDeviceObject);
				return status;
			}
			DbgPrint("[+] Initializing Sym Info\n");
			if (!InitSymInfo()) {
				DbgPrint("[-] Failed to initialize symbol information\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
		DbgPrint("[+] Initializing INIT Data %llx\n", status);
		if (!InitData()) {
			DbgPrint("[-] Failed to initialize data\n");
			return STATUS_UNSUCCESSFUL;
		}
		else {
			if (gSourceProcess != NULL && gInit.requestedProtection != 0x0) {
				ChangeMemoryProtection(gSourceProcess, gInit.sourceVA, 4096, gInit.requestedProtection);
				gInit.requestedProtection = 0x0;
			}
			else {
				DbgPrint("Skip protect\n");
			}
		}
		DbgPrint("[+] Finished initializing data and symbol information\n");
		DbgPrint("[+] Source Process: %s\n", gInit.sourceProcess);
		DbgPrint("[+] Target Process: %s\n", gInit.targetProcess);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID WritePhysicalWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0;
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] WritePhysicalWorkerThread: wait failed %08X\n", status);
			break;
		}

		if (gWritePhysSection == NULL) {
			DbgPrint("[-] WritePhysicalWorkerThread: gWritePhysSection is NULL\n");
			continue;
		}

		WRITE_PHYS_REQUEST req;
		RtlCopyMemory(&req, gWritePhysSection, sizeof(req));

		if (!req.isValid || memcmp(req.identifier, "WPHY", 4) != 0) {
			DbgPrint("[-] WritePhysicalWorkerThread: invalid request (isValid=%d)\n", req.isValid);
			continue;
		}
		if (req.dataSize == 0 || req.dataSize > MAX_WRITE_BUFFER_SIZE) {
			DbgPrint("[-] WritePhysicalWorkerThread: bad dataSize %lu\n", req.dataSize);
			RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
			continue;
		}

		// Use whichever process gInit has been set to (UpdateInitData was called by usermode)
		const char* procName = gInit.targetProcess[0] ? gInit.targetProcess : gInit.sourceProcess;
		PEPROCESS pProc = GetProcessByName(procName, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		if (!pProc) {
			DbgPrint("[-] WritePhysicalWorkerThread: process '%s' not found\n", procName);
			RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
			continue;
		}
		unsigned long long cr3 = GetDirectoryTableBaseByName(procName,
			gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);

		unsigned long long physBase = 0, pageOff = 0;
		// WalkPageTablesGetPhysPage uses MmCopyMemory MM_COPY_MEMORY_PHYSICAL only —
		// no virtual address context is needed; do NOT attach to the process here.
		status = WalkPageTablesGetPhysPage(req.targetVA, cr3, &physBase, &pageOff);

		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] WritePhysicalWorkerThread: page walk failed %08X for VA 0x%llx\n", status, req.targetVA);
			RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
			continue;
		}

		// physBase = page-aligned physical base; pageOff = va & 0xFFF;
		// offsetInPage = additional byte offset within the page supplied by usermode
		unsigned long long writePhys = physBase + pageOff + req.offsetInPage;
		if ((pageOff + req.offsetInPage + req.dataSize) > PAGE_SIZE) {
			DbgPrint("[!] WritePhysicalWorkerThread: truncating write to page boundary\n");
			req.dataSize = (ULONG)(PAGE_SIZE - pageOff - req.offsetInPage);
		}

		DbgPrint("[+] WritePhysicalWorkerThread: VA=0x%llx physBase=0x%llx off=0x%llx writeAt=0x%llx size=%lu\n",
			req.targetVA, physBase, pageOff, writePhys, req.dataSize);

		SIZE_T bytesWritten = 0;
		status = WritePhysicalAddress((PVOID)writePhys, req.data, req.dataSize, &bytesWritten);
		if (NT_SUCCESS(status))
			DbgPrint("[+] WritePhysicalWorkerThread: wrote %zu bytes to 0x%llx\n", bytesWritten, writePhys);
		else
			DbgPrint("[-] WritePhysicalWorkerThread: write failed %08X\n", status);

		RtlZeroMemory(gWritePhysSection, sizeof(WRITE_PHYS_REQUEST));
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID ReadPhysicalWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		pEvent->Header.SignalState = 0;
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] ReadPhysicalWorkerThread: wait failed %08X\n", status);
			break;
		}

		if (gReadPhysSection == NULL) {
			DbgPrint("[-] ReadPhysicalWorkerThread: gReadPhysSection is NULL\n");
			continue;
		}

		PREAD_PHYS_REQUEST req = (PREAD_PHYS_REQUEST)gReadPhysSection;

		if (!req->isValid || memcmp(req->identifier, "RPHY", 4) != 0) {
			DbgPrint("[-] ReadPhysicalWorkerThread: invalid request (isValid=%d)\n", req->isValid);
			continue;
		}
		if ((PVOID)req->targetVirtualAddress == NULL) {
			DbgPrint("[-] ReadPhysicalWorkerThread: targetVirtualAddress is NULL\n");
			req->isValid = FALSE;
			continue;
		}

		// Use whichever process gInit has been set to (UpdateInitData was called by usermode)
		const char* procName = gInit.targetProcess[0] ? gInit.targetProcess : gInit.sourceProcess;
		if (!procName || !procName[0]) {
			DbgPrint("[-] ReadPhysicalWorkerThread: no process set in gInit\n");
			req->isValid = FALSE;
			continue;
		}

		PEPROCESS pProc = GetProcessByName(procName, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		if (!pProc) {
			DbgPrint("[-] ReadPhysicalWorkerThread: process '%s' not found\n", procName);
			req->isValid = FALSE;
			continue;
		}
		unsigned long long cr3 = GetDirectoryTableBaseByName(procName,
			gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
		if (!cr3) {
			DbgPrint("[-] ReadPhysicalWorkerThread: CR3=0 for '%s'\n", procName);
			req->isValid = FALSE;
			continue;
		}

		DbgPrint("[+] ReadPhysicalWorkerThread: VA=0x%p process='%s'\n",
			req->targetVirtualAddress, procName);

		unsigned long long physBase = 0, pageOff = 0;
		status = WalkPageTablesGetPhysPage((unsigned long long)req->targetVirtualAddress, cr3, &physBase, &pageOff);

		if (!NT_SUCCESS(status)) {
			// Suppress per-page failure noise during bulk dump reads —
			// usermode detects failure via identifier[0] != 0.
			req->isValid = FALSE;
			continue;
		}

		// Read the full page so usermode can index any offset within it
		SIZE_T bytesRead = 0;
		status = ReadPhysicalAddress((PVOID)physBase, req->pageData, PAGE_SIZE, &bytesRead);
		if (NT_SUCCESS(status)) {
			RtlZeroMemory(req->identifier, 4); // signal success to usermode; data stays
		} else {
			RtlZeroMemory(req, sizeof(READ_PHYS_REQUEST));
		}
		req->isValid = FALSE;
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

// =================================================================
// VadInsertWorkerThread
// Waits for hEventVAD_INSERT. Reads a VAD_MODIFY_REQUEST with
// identifier "VINS", allocates a minimal MMVAD-compatible node,
// fills the VPN range and flags, then calls VadTreeInsert.
// Result NTSTATUS is written back to the request before isValid=FALSE.
// =================================================================
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
#define SFND_VAD_STACK 256
VOID VadInsertWorkerThread(PVOID Context) {
    PKEVENT          pEvent = (PKEVENT)Context;
    PVAD_MODIFY_REQUEST req;
    PEPROCESS        pTarget;
    PVOID            newNode;
    NTSTATUS         status;
    SIZE_T           nodeSize;
    unsigned long long qw;
    unsigned long long high;
    UCHAR            liveWalkMode;
    const char*      procName;
    /* SFND locals — declared here because C89 forbids decls after goto labels */
    PVOID            sfndVadStack[SFND_VAD_STACK];

    while (!g_StopRequested) {
        status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] VadInsertWorkerThread: wait failed %08X\n", status);
            break;
        }
        KeClearEvent(pEvent);

        if (!gVadModifySection) {
            DbgPrint("[-] VadInsertWorkerThread: gVadModifySection is NULL\n");
            continue;
        }

        req = (PVAD_MODIFY_REQUEST)gVadModifySection;

        // Spin-wait briefly for isValid — SetEvent from userland may arrive
        // fractionally before the shared-memory write is visible in our view.
        if (!req->isValid) {
            for (int spin = 0; spin < 200 && !req->isValid; spin++)
                KeStallExecutionProcessor(50); // 50us per iteration, max 10ms
        }
        if (!req->isValid) {
            // Genuine spurious wake — silently loop back without logging.
            continue;
        }

        // -- QHNT: query VadFreeHint ? return the suggested next-free StartingVpn --
        if (memcmp(req->identifier, "QHNT", 4) == 0) {
            // Walk the same tree that was last populated: source for mode=1, target for mode=0/2
            liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;
            procName     = (liveWalkMode == 1) ? gInit.sourceProcess : gInit.targetProcess;
            PEPROCESS pQ = GetProcessByName(procName,
                gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
            if (!pQ) {
                DbgPrint("[-] QHNT: process '%s' not found\n", procName);
                req->Result  = STATUS_NOT_FOUND;
                req->isValid = FALSE;
                continue;
            }

            // The MMVAD stores only 40 bits of VPN (32-bit low + 8-bit high).
            // A user-mode process VAD tree has NO kernel-space nodes, so we can't
            // use the canonical hole as a split point.  Instead divide the 40-bit
            // VPN space in half:
            //   low  (= 0x3FFFFFFFF): private heap/stack/data allocations
            //   high (> 0x3FFFFFFFF): system DLL / high-VA area (0x7FF... range)
            // This naturally separates the two allocation zones in any user process.
            // For a kernel process walk, actual kernel VPNs (0xFFxx_xxxxxxxx after
            // 40-bit truncation) are >> 0x3FFFFFFFF and land in the high bucket too.
            #define USER_MAX_VPN   0x7FFFFFFFFull
            #define KERNEL_MIN_VPN 0x400000000ull  // upper half of 40-bit VPN space

            // Full in-order BST walk: track the maximum EndingVpn seen in each
            // address space independently.  Single pass, explicit stack.
            {
                PVOID* pVadRoot = (PVOID*)((ULONG_PTR)pQ + gSymInfo.VADRoot);
                PVOID  vadRoot  = (pVadRoot && MmIsAddressValid(pVadRoot)) ? *pVadRoot : NULL;

                unsigned long long maxUserEndVpn   = 0;
                unsigned long long maxKernelEndVpn = 0;

                #define QHNT_STACK_DEPTH 64
                PVOID qstack[QHNT_STACK_DEPTH];
                int   qtop = 0;
                PVOID cur  = vadRoot;

                while ((cur && MmIsAddressValid(cur)) || qtop > 0) {
                    while (cur && MmIsAddressValid(cur)) {
                        if (qtop < QHNT_STACK_DEPTH) qstack[qtop++] = cur;
                        cur = *(PVOID*)((ULONG_PTR)cur + gSymInfo.Left);
                    }
                    if (qtop == 0) break;
                    cur = qstack[--qtop];

                    ULONG endLow  = *(ULONG*)((ULONG_PTR)cur + gSymInfo.EndingVpnOffset);
                    UCHAR endHigh = *(UCHAR*)((ULONG_PTR)cur + gSymInfo.EndingVpnOffset + 5);
                    unsigned long long endVpn = (unsigned long long)endLow | ((unsigned long long)endHigh << 32);

                    if (endVpn >= KERNEL_MIN_VPN) {
                        if (endVpn > maxKernelEndVpn) maxKernelEndVpn = endVpn;
                    } else {
                        if (endVpn > maxUserEndVpn) maxUserEndVpn = endVpn;
                    }

                    cur = *(PVOID*)((ULONG_PTR)cur + gSymInfo.Right);
                }
                #undef QHNT_STACK_DEPTH

                // User suggestion
                if (maxUserEndVpn > 0 && (maxUserEndVpn + 1) <= USER_MAX_VPN)
                    req->SuggestedUserVpn = maxUserEndVpn + 1;
                else
                    req->SuggestedUserVpn = 0;

                // Kernel suggestion
                if (maxKernelEndVpn > 0) {
                    unsigned long long ksugg = maxKernelEndVpn + 1;
                    req->SuggestedKernelVpn = (ksugg >= KERNEL_MIN_VPN) ? ksugg : 0;
                } else {
                    req->SuggestedKernelVpn = 0;
                }

                DbgPrint("[+] QHNT: process='%s' userSugg=0x%llx kernelSugg=0x%llx\n",
                    procName, req->SuggestedUserVpn, req->SuggestedKernelVpn);
            }

            req->Result  = STATUS_SUCCESS;
            req->isValid = FALSE;
            continue;
        }

        if (memcmp(req->identifier, "OPRC", 4) == 0) {
            const char* targetName = gInit.targetProcess[0]
                ? gInit.targetProcess : gInit.sourceProcess;
            const char* sourceName = gInit.sourceProcess;
            DbgPrint("[*] OPRC: target='%s' source='%s'\n", targetName, sourceName);

            PEPROCESS pTarget = GetProcessByName(targetName,
                gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
            PEPROCESS pSource = GetProcessByName(sourceName,
                gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);

            if (!pTarget || !pSource) {
                DbgPrint("[-] OPRC: process not found target='%s' source='%s'\n",
                    targetName, sourceName);
                req->HandleResult = 0;
                req->Result       = STATUS_NOT_FOUND;
                req->isValid      = FALSE;
                continue;
            }

            ACCESS_MASK desiredAccess = req->Protection
                ? (ACCESS_MASK)req->Protection : PROCESS_ALL_ACCESS;

            HANDLE hKernelTarget = NULL;
            NTSTATUS oprcStatus = ObOpenObjectByPointer(
                pTarget, OBJ_KERNEL_HANDLE, NULL,
                desiredAccess, *PsProcessType, KernelMode, &hKernelTarget);
            if (!NT_SUCCESS(oprcStatus)) {
                DbgPrint("[-] OPRC: ObOpenObjectByPointer(target) failed %08X\n", oprcStatus);
                req->HandleResult = 0;
                req->Result       = oprcStatus;
                req->isValid      = FALSE;
                continue;
            }

            HANDLE hKernelSource = NULL;
            oprcStatus = ObOpenObjectByPointer(
                pSource, OBJ_KERNEL_HANDLE, NULL,
                PROCESS_DUP_HANDLE, *PsProcessType, KernelMode, &hKernelSource);
            if (!NT_SUCCESS(oprcStatus)) {
                DbgPrint("[-] OPRC: ObOpenObjectByPointer(source) failed %08X\n", oprcStatus);
                ZwClose(hKernelTarget);
                req->HandleResult = 0;
                req->Result       = oprcStatus;
                req->isValid      = FALSE;
                continue;
            }

            HANDLE hDuplicated = NULL;
            oprcStatus = ZwDuplicateObject(
                ZwCurrentProcess(), hKernelTarget,
                hKernelSource,      &hDuplicated,
                desiredAccess, 0, DUPLICATE_SAME_ACCESS);

            ZwClose(hKernelTarget);
            ZwClose(hKernelSource);

            if (!NT_SUCCESS(oprcStatus)) {
                DbgPrint("[-] OPRC: ZwDuplicateObject failed %08X\n", oprcStatus);
                req->HandleResult = 0;
                req->Result       = oprcStatus;
                req->isValid      = FALSE;
                continue;
            }

            DbgPrint("[+] OPRC: handle 0x%p for '%s' -> '%s'\n",
                hDuplicated, targetName, sourceName);
            req->HandleResult = (unsigned long long)(ULONG_PTR)hDuplicated;
            req->Result       = STATUS_SUCCESS;
            req->isValid      = FALSE;
            continue;
        }

        // PPRT: temporarily zero or restore EPROCESS.Protection on the target
        // so that DbgHelp can call NtSuspendProcess on PPL/protected processes.
        // req->Protection = 0 ? clear (before dump); non-zero ? restore saved byte.
        // req->HandleResult is used to pass the saved byte back to userland.
        if (memcmp(req->identifier, "PPRT", 4) == 0) {
            const char* pprtName = gInit.targetProcess[0]
                ? gInit.targetProcess : gInit.sourceProcess;
            PEPROCESS pTarget = GetProcessByName(pprtName,
                gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);

            if (!pTarget || gSymInfo.EProcProtectionOffset == 0) {
                DbgPrint("[-] PPRT: process not found or Protection offset unknown\n");
                req->Result  = STATUS_NOT_FOUND;
                req->isValid = FALSE;
                continue;
            }

            PUCHAR pProtByte = (PUCHAR)((ULONG_PTR)pTarget + gSymInfo.EProcProtectionOffset);

            if (req->Protection == 0) {
                // Clear: save current value, zero the byte
                req->HandleResult = *pProtByte;
                *pProtByte = 0;
                DbgPrint("[+] PPRT: cleared Protection on '%s' (was 0x%02X)\n",
                    pprtName, (UCHAR)req->HandleResult);
            } else {
                // Restore: write back the saved byte passed in Protection
                *pProtByte = (UCHAR)req->Protection;
                DbgPrint("[+] PPRT: restored Protection on '%s' to 0x%02X\n",
                    pprtName, (UCHAR)req->Protection);
            }

            req->Result  = STATUS_SUCCESS;
            req->isValid = FALSE;
            continue;
        }

        // SFND: find all processes that have a VAD backed by TargetControlArea.
        if (memcmp(req->identifier, "SFND", 4) == 0) {
            PSFND_RESULT sr = (PSFND_RESULT)req;
            ULONG64      targetCA;
            PVOID        startProc, currProc;
            typedef NTSTATUS (*PFN_ObQueryNameString)(PVOID, POBJECT_NAME_INFORMATION, ULONG, PULONG);
            PFN_ObQueryNameString fnQNS;
            UNICODE_STRING        usFnName;

            targetCA   = sr->TargetControlArea;
            sr->Count  = 0;
            sr->Result = STATUS_SUCCESS;

            //DbgPrint("[*] SFND: searching CA=0x%llx\n", targetCA);

            if (!targetCA || !gSymInfo.VADRoot || !gSymInfo.EProcActiveProcessLinks ||
                !gSymInfo.EProcImageFileName || !gSymInfo.MMVADSubsection ||
                !gSymInfo.StartingVpnOffset) {
                //DbgPrint("[-] SFND: missing offsets or null CA\n");
                sr->Result  = STATUS_INVALID_PARAMETER;
                sr->isValid = FALSE;
                continue;
            }

            fnQNS = NULL;
            RtlInitUnicodeString(&usFnName, L"ObQueryNameString");
            fnQNS = (PFN_ObQueryNameString)MmGetSystemRoutineAddress(&usFnName);

            startProc = PsGetCurrentProcess();
            currProc  = startProc;

            do {
                int         top;
                PVOID       vadRoot;
                PVOID*      pVadRoot;
                PVOID       node, rc, lc;
                ULONG       vf;
                ULONG_PTR   subPtr, ca;
                ULONG64     vpnQw, hiBytes;
                PSFND_ENTRY e;
                PCHAR       img;
                ULONG       dummy1, dummy2, ci, chars, returned;
                ULONG64     dummy3;
                UNICODE_STRING*          fn;
                UCHAR                    nameBuf[512];
                POBJECT_NAME_INFORMATION oni;

                if (!MmIsAddressValid(currProc)) break;

                pVadRoot = (PVOID*)((ULONG_PTR)currProc + gSymInfo.VADRoot);
                if (!MmIsAddressValid(pVadRoot)) goto sfnd_next;
                vadRoot = *pVadRoot;
                if (!vadRoot || !MmIsAddressValid(vadRoot)) goto sfnd_next;

                top = 0;
                sfndVadStack[top++] = vadRoot;

                while (top > 0 && sr->Count < SFND_MAX_ENTRIES) {
                    node = sfndVadStack[--top];
                    if (!node || !MmIsAddressValid(node)) continue;

                    rc = *(PVOID*)((ULONG_PTR)node + gSymInfo.Right);
                    lc = *(PVOID*)((ULONG_PTR)node + gSymInfo.Left);
                    if (rc && MmIsAddressValid(rc) && top < SFND_VAD_STACK - 1) sfndVadStack[top++] = rc;
                    if (lc && MmIsAddressValid(lc) && top < SFND_VAD_STACK - 1) sfndVadStack[top++] = lc;

                    if (!gSymInfo.PrivateMemoryBitPos || gSymInfo.PrivateMemoryBitPos >= 32) continue;
                    vf = *(ULONG*)((ULONG_PTR)node + gSymInfo.MMVADFlagsOffset);
                    if ((vf >> gSymInfo.PrivateMemoryBitPos) & 1u) continue;

                    subPtr = *(ULONG_PTR*)((ULONG_PTR)node + gSymInfo.MMVADSubsection);
                    if (!subPtr || !MmIsAddressValid((PVOID)subPtr)) continue;

                    ca = *(ULONG_PTR*)subPtr;
                    if (ca != (ULONG_PTR)targetCA) continue;

                    e = &sr->Entries[sr->Count];
                    vpnQw   = *(ULONG64*)((ULONG_PTR)node + gSymInfo.StartingVpnOffset);
                    hiBytes = *(ULONG64*)((ULONG_PTR)node + 0x20);
                    e->ControlAreaPtr = ca;
                    e->StartingVpn    = (vpnQw & 0xFFFFFFFF)         | (((hiBytes)       & 0xFF) << 32);
                    e->EndingVpn      = ((vpnQw >> 32) & 0xFFFFFFFF) | (((hiBytes >> 8)  & 0xFF) << 32);
                    e->Pid            = (ULONG)(ULONG_PTR)PsGetProcessId((PEPROCESS)currProc);

                    { ULONG bp = gSymInfo.ProtectionBitPos; e->Protection = (bp < 29) ? ((vf >> bp) & 0x1Fu) : 0u; }

                    img = (PCHAR)((ULONG_PTR)currProc + gSymInfo.EProcImageFileName);
                    RtlCopyMemory(e->ImageName, img, 15);
                    e->ImageName[15] = '\0';

                    e->HasFileName = FALSE; e->FileName[0] = '\0';
                    e->HasObjName  = FALSE; e->ObjName[0]  = '\0';
                    fn = NULL;

                    if (gSymInfo.MMVADControlArea && gSymInfo.MMVADCAFilePointer && gSymInfo.FILEOBJECTFileName) {
                        dummy1 = 0; dummy2 = 0; dummy3 = 0;
                        fn = GetFileObjectFromVADLeaf(
                            (ULONG_PTR)node,
                            gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
                            gSymInfo.MMVADCAFilePointer, gSymInfo.MMCAFlags,
                            gSymInfo.FILEOBJECTFileName,
                            &dummy1, &dummy2, &dummy2, &dummy3);
                    }

                    if (fn && fn->Length > 0 && MmIsAddressValid(fn->Buffer)) {
                        // File-backed: copy FileName and get full device path via ObQueryNameString
                        chars = fn->Length / sizeof(WCHAR);
                        if (chars > sizeof(e->FileName) - 1) chars = (ULONG)(sizeof(e->FileName) - 1);
                        for (ci = 0; ci < chars; ci++)
                            e->FileName[ci] = (fn->Buffer[ci] < 128) ? (CHAR)fn->Buffer[ci] : '?';
                        e->FileName[chars] = '\0';
                        e->HasFileName = (e->FileName[0] != '\0');

                        if (fnQNS && gSymInfo.FILEOBJECTFileName) {
                            PVOID fileObj = (PVOID)((ULONG_PTR)fn - gSymInfo.FILEOBJECTFileName);
                            oni = (POBJECT_NAME_INFORMATION)nameBuf;
                            returned = 0;
                            if (MmIsAddressValid(fileObj) &&
                                NT_SUCCESS(fnQNS(fileObj, oni, sizeof(nameBuf), &returned)) &&
                                oni->Name.Length > 0 && MmIsAddressValid(oni->Name.Buffer)) {
                                ULONG nc = oni->Name.Length / sizeof(WCHAR);
                                if (nc > sizeof(e->ObjName) - 1) nc = (ULONG)(sizeof(e->ObjName) - 1);
                                for (ci = 0; ci < nc; ci++)
                                    e->ObjName[ci] = (oni->Name.Buffer[ci] < 128) ? (CHAR)oni->Name.Buffer[ci] : '?';
                                e->ObjName[nc] = '\0';
                                e->HasObjName = (e->ObjName[0] != '\0');
                            }
                        }
                    } else {
                        // Page-file-backed named section (e.g. \BaseNamedObjects\MySharedMemory).
                        // Strategy:
                        //   1. CA->Segment (CASegmentOffset=0: first field of _CONTROL_AREA)
                        //   2. Attach to the matched process, scan its handle table
                        //   3. ObReferenceObjectByHandle(*MmSectionObjectType) -> _SECTION*
                        //   4. _SECTION.u1.Segment (SectionSegmentOffset=0) == pSegment => match
                        //   5. Walk back: objHdr = objPtr - ObjHdrSize
                        //   6. InfoMask & 0x2 => _OBJECT_HEADER_NAME_INFO at objHdr - ObjHdrNameInfoSize
                        //   7. Name UNICODE_STRING at offset 0 of NAME_INFO

                        //DbgPrint("[*] SFND: pagefile path CA=0x%llx ObjHdrSize=%u InfoMaskOff=%u NameInfoSz=%u\n",
                        //    targetCA, gSymInfo.ObjHdrSize, gSymInfo.ObjHdrInfoMaskOffset, gSymInfo.ObjHdrNameInfoSize);

                        // NOTE: CASegmentOffset and SectionSegmentOffset are legitimately 0
                        // (_CONTROL_AREA.Segment and _SECTION.u1 are both the first fields).
                        // Do NOT guard on them being non-zero.
                        if (gSymInfo.ObjHdrSize && gSymInfo.ObjHdrInfoMaskOffset &&
                            gSymInfo.ObjHdrNameInfoSize && MmIsAddressValid((PVOID)targetCA)) {

                            PVOID pSegment = *(PVOID*)((ULONG_PTR)targetCA + gSymInfo.CASegmentOffset);
                            //DbgPrint("[*] SFND: pSegment=0x%p fnQNS=0x%p SectionSegOff=%u CASegOff=%u\n",
                            //    pSegment, fnQNS, gSymInfo.SectionSegmentOffset, gSymInfo.CASegmentOffset);

                            if (pSegment && MmIsAddressValid(pSegment)) {
                                // Enumerate all handles system-wide via ZwQuerySystemInformation
                                // (class 16 = SystemHandleInformation).  This gives us the kernel
                                // object pointer for every Section handle in every process —
                                // including System (pid=4) and smss.exe whose handles are
                                // OBJ_KERNEL_HANDLE (bit-31 set) and therefore NOT present in
                                // the per-process user-mode handle table.  Scanning those tables
                                // with ObReferenceObjectByHandle triggers bugcheck 0x93.
                                // ObQueryNameString is then called directly on the kernel object
                                // pointer with no process attachment required.
                                typedef struct { USHORT Pid; USHORT Trace; UCHAR TypeIdx; UCHAR Attr; USHORT Handle; PVOID Object; ULONG Access; } _SHE;
                                typedef struct { ULONG Count; _SHE Entries[1]; } _SHI;

                                BOOLEAN localFound = FALSE;
                                CHAR    localName[sizeof(e->ObjName)];
                                RtlZeroMemory(localName, sizeof(localName));

                                if (fnQNS) {
                                    ULONG   bufSize = 512 * 1024;
                                    _SHI*   shi     = NULL;
                                    NTSTATUS qst;
                                    ULONG   retLen  = 0;
                                    do {
                                        if (shi) ExFreePoolWithTag(shi, 'SFND');
                                        shi = (_SHI*)ExAllocatePoolWithTag(PagedPool, bufSize, 'SFND');
                                        if (!shi) break;
                                        qst = ZwQuerySystemInformation(16, shi, bufSize, &retLen);
                                        if (qst == STATUS_INFO_LENGTH_MISMATCH)
                                            bufSize = retLen + 0x1000;
                                    } while (qst == STATUS_INFO_LENGTH_MISMATCH);

                                    if (shi && NT_SUCCESS(qst)) {
                                        for (ULONG hi = 0; hi < shi->Count && !localFound; hi++) {
                                            PVOID objPtr = shi->Entries[hi].Object;
                                            if (!objPtr) continue;
                                            __try {
                                                // Scan _SECTION body for a slot equal to targetCA
                                                // (_SECTION.u1 = _CONTROL_AREA* confirmed at +0x28).
                                                BOOLEAN caMatch = FALSE;
                                                ULONG scanOff;
                                                for (scanOff = 0; scanOff < 0x80 && !caMatch; scanOff += 8) {
                                                    PVOID* loc = (PVOID*)((ULONG_PTR)objPtr + scanOff);
                                                    if (*loc == (PVOID)(ULONG_PTR)targetCA)
                                                        caMatch = TRUE;
                                                }
                                                if (!caMatch) continue;

                                                // Get name directly from the kernel object header —
                                                // no process attachment needed.
                                                UCHAR nbuf[512];
                                                POBJECT_NAME_INFORMATION oni2 = (POBJECT_NAME_INFORMATION)nbuf;
                                                ULONG rlen2 = 0;
                                                if (NT_SUCCESS(fnQNS(objPtr, oni2, sizeof(nbuf), &rlen2)) &&
                                                    oni2->Name.Length > 0 && oni2->Name.Buffer &&
                                                    MmIsAddressValid(oni2->Name.Buffer)) {
                                                    ULONG nc = oni2->Name.Length / sizeof(WCHAR);
                                                    if (nc > sizeof(localName) - 1) nc = (ULONG)(sizeof(localName) - 1);
                                                    ULONG nci;
                                                    for (nci = 0; nci < nc; nci++)
                                                        localName[nci] = (oni2->Name.Buffer[nci] < 128) ? (CHAR)oni2->Name.Buffer[nci] : '?';
                                                    localName[nc] = '\0';
                                                    localFound = (localName[0] != '\0');
                                                    if (localFound)
                                                       ;//DbgPrint("[+] SFND: ObjName=%s (pid=%u h=0x%x)\n",
                                                       //    localName, shi->Entries[hi].Pid, shi->Entries[hi].Handle);
                                                }
                                            } __except (EXCEPTION_EXECUTE_HANDLER) {}
                                        }
                                    }
                                    if (shi) ExFreePoolWithTag(shi, 'SFND');
                                }

                                if (localFound) {
                                    RtlCopyMemory(e->ObjName, localName, sizeof(localName));
                                    e->HasObjName = TRUE;
                                } else {
                                    //DbgPrint("[-] SFND: no name found for CA=0x%llx\n", targetCA);
                                }
                            }
                        } else {
                            //DbgPrint("[-] SFND: pagefile block skipped ObjHdrSize=%u InfoMaskOff=%u NameInfoSz=%u validCA=%d\n",
                            //    gSymInfo.ObjHdrSize, gSymInfo.ObjHdrInfoMaskOffset, gSymInfo.ObjHdrNameInfoSize,
                            //    MmIsAddressValid((PVOID)targetCA));
                        }
                    }

                    sr->Count++;
                }

sfnd_next:
                {
                    PLIST_ENTRY le = (PLIST_ENTRY)((ULONG_PTR)currProc + gSymInfo.EProcActiveProcessLinks);
                    if (!MmIsAddressValid(le) || !MmIsAddressValid(le->Flink)) break;
                    currProc = (PVOID)((ULONG_PTR)le->Flink - gSymInfo.EProcActiveProcessLinks);
                }
            } while (currProc != startProc && MmIsAddressValid(currProc));

            //DbgPrint("[+] SFND: CA=0x%llx found in %lu process(es)\n", targetCA, sr->Count);

            // Propagate the object name found in any one process to all entries
            // that share the same CA — the name is on the Section object itself and
            // is identical regardless of which process handle we found it via.
            if (sr->Count > 1) {
                CHAR sharedName[sizeof(sr->Entries[0].ObjName)];
                RtlZeroMemory(sharedName, sizeof(sharedName));
                ULONG ei;
                for (ei = 0; ei < sr->Count; ei++) {
                    if (sr->Entries[ei].HasObjName) {
                        RtlCopyMemory(sharedName, sr->Entries[ei].ObjName, sizeof(sharedName));
                        break;
                    }
                }
                if (sharedName[0] != '\0') {
                    for (ei = 0; ei < sr->Count; ei++) {
                        if (!sr->Entries[ei].HasObjName) {
                            RtlCopyMemory(sr->Entries[ei].ObjName, sharedName, sizeof(sharedName));
                            sr->Entries[ei].HasObjName = TRUE;
                        }
                    }
                }
            }

            sr->isValid = FALSE;
            continue;
        }

        if (memcmp(req->identifier, "VINS", 4) != 0) {
            DbgPrint("[-] VadInsertWorkerThread: unknown identifier, discarding\n");
            req->Result  = STATUS_INVALID_PARAMETER;
            req->isValid = FALSE;
            continue;
        }


        liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;
        procName     = (liveWalkMode == 1) ? gInit.sourceProcess : gInit.targetProcess;
        pTarget = GetProcessByName(procName,
            gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
        if (!pTarget) {
            DbgPrint("[-] VadInsertWorkerThread: process '%s' not found\n", procName);
            req->Result  = STATUS_NOT_FOUND;
            req->isValid = FALSE;
            continue;
        }

        // -- Step 1: allocate and initialise node -------------------------
        PVOID pChainCA   = NULL;
        PVOID pChainSeg  = NULL;
        PVOID pChainPTEs = NULL;
        BOOLEAN isPrivateNode = (gSymInfo.PrivateMemoryBitPos < 32)
            ? (BOOLEAN)((req->VadTypeRaw >> gSymInfo.PrivateMemoryBitPos) & 1u)
            : TRUE;
        ULONG vadTypeVal = (gSymInfo.VadTypeBitPos < 32)
            ? ((req->VadTypeRaw >> gSymInfo.VadTypeBitPos) & 0x7u)
            : 0u;
        BOOLEAN isReuseCA = (req->ReuseCA != 0);

        if (!isPrivateNode) {
            if (isReuseCA) {
                // Reuse an existing _CONTROL_AREA from a prior VINS call.
                // Validate the pointer is still kernel-accessible before touching it.
                pChainCA = (PVOID)(ULONG_PTR)req->ReuseCA;
                if (!MmIsAddressValid(pChainCA)) {
                    DbgPrint("[-] VadInsertWorkerThread: ReuseCA 0x%llx is not a valid address\n", req->ReuseCA);
                    req->Result  = STATUS_INVALID_ADDRESS;
                    req->isValid = FALSE;
                    continue;
                }
                // pChainPTEs lives at Seg->PrototypePte (Seg = CA+0x00 deref, then +0x40)
                PVOID pSeg = *(PVOID*)((ULONG_PTR)pChainCA + 0x00);
                if (pSeg && MmIsAddressValid(pSeg))
                    pChainPTEs = *(PVOID*)((ULONG_PTR)pSeg + 0x40);
                // Bump NumberOfMappedViews [CA+0x28] atomically.
                InterlockedIncrement((volatile LONG*)((ULONG_PTR)pChainCA + 0x28));
                DbgPrint("[+] VadInsertWorkerThread: reusing CA=0x%p MappedViews=%lu\n",
                    pChainCA, *(ULONG*)((ULONG_PTR)pChainCA + 0x28));
                // pChainSeg/pChainPTEs are NOT freed on this path — they belong to the
                // original VINS allocation and must outlive all sharing nodes.
                pChainSeg = NULL; // do not free
            } else {
                unsigned long long totalPages = (req->EndingVpn >= req->StartingVpn)
                    ? (req->EndingVpn - req->StartingVpn + 1) : 1;
                ULONG mmProt = (gSymInfo.ProtectionBitPos < 32)
                    ? ((req->VadTypeRaw >> gSymInfo.ProtectionBitPos) & 0x1Fu)
                    : 0x04u;
                NTSTATUS chainStatus = AllocateSubsectionChain(totalPages, vadTypeVal, mmProt, &pChainCA, &pChainSeg, &pChainPTEs);
                if (!NT_SUCCESS(chainStatus)) {
                    DbgPrint("[-] VadInsertWorkerThread: AllocateSubsectionChain failed %08X\n", chainStatus);
                    req->Result  = chainStatus;
                    req->isValid = FALSE;
                    continue;
                }
            }
        }
        nodeSize = req->NodeSize ? req->NodeSize : 0x80;
        newNode  = NULL;
        status   = VadAllocateNode(nodeSize, &newNode);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] VadInsertWorkerThread: VadAllocateNode failed %08X\n", status);
            req->Result  = status;
            req->isValid = FALSE;
            continue;
        }

        // Encode StartingVpn / EndingVpn at StartingVpnOffset
        qw   = (req->StartingVpn & 0xFFFFFFFF) | ((req->EndingVpn & 0xFFFFFFFF) << 32);
        *(unsigned long long*)((ULONG_PTR)newNode + gSymInfo.StartingVpnOffset) = qw;
        // High bytes at +0x20 (StartingVpnHigh[7:0] | EndingVpnHigh[7:0]<<8)
        high = (req->StartingVpn >> 32) & 0xFF;
        high |= ((req->EndingVpn >> 32) & 0xFF) << 8;
        *(unsigned long long*)((ULONG_PTR)newNode + 0x20) = high;
        // MMVAD_FLAGS at PDB-derived offset (replaces hardcoded 0x30)
        *(ULONG*)((ULONG_PTR)newNode + gSymInfo.MMVADFlagsOffset) = req->VadTypeRaw;

        // Wire Subsection, FirstPrototypePte and LastContiguousPte for non-private nodes.
        //
        // MUST use the PDB-derived MMVADSubsection offset — NOT a hardcoded constant.
        // MiInsertVadCharges calls MiVadPureReserve which reads node+MMVADSubsection to
        // locate the Subsection.  If the offset is wrong MiVadPureReserve gets NULL,
        // treats the VAD as pure reserve, skips MiCommitPageTablesForVad and
        // MiSetVadBits ? no page-table structures ? VirtualQuery returns MEM_MAPPED
        // without MEM_COMMIT.
        //
        // FirstPrototypePte  (node + MMVADSubsection + 8)  — pointer to the first
        //   prototype PTE for this VAD's range.  MiDispatchFault reads this to locate
        //   the demand-zero PTE when a page fault fires.  NULL here = unresolvable fault
        //   = access violation on every access, regardless of commit state.
        //
        // LastContiguousPte  (node + MMVADSubsection + 16) — inclusive pointer to the
        //   last valid prototype PTE.  Used as an upper-bounds check by the fault handler.
        //   For a single-page VAD FirstPrototypePte == LastContiguousPte.
        if (!isPrivateNode && pChainCA && pChainPTEs && gSymInfo.MMVADSubsection) {
            PVOID pSub = (PVOID)((ULONG_PTR)pChainCA + 0x80);
            unsigned long long wirePages = (req->EndingVpn >= req->StartingVpn)
                ? (req->EndingVpn - req->StartingVpn + 1) : 1;

            // Subsection pointer
            *(PVOID*)((ULONG_PTR)newNode + gSymInfo.MMVADSubsection) = pSub;

            // FirstPrototypePte — first PTE in the array (pPTEs[0])
            *(PVOID*)((ULONG_PTR)newNode + gSymInfo.MMVADSubsection + sizeof(PVOID)) = pChainPTEs;

            // LastContiguousPte — last valid PTE in the array (pPTEs[wirePages-1], inclusive)
            *(PVOID*)((ULONG_PTR)newNode + gSymInfo.MMVADSubsection + 2 * sizeof(PVOID)) =
                (PVOID)((ULONG_PTR)pChainPTEs + (wirePages - 1) * sizeof(ULONG64));

            // ViewLinks at MMVADSubsection+0x18 — must be a valid self-referencing
            // empty LIST_ENTRY before insertion.  MiDeleteVad calls RemoveEntryList
            // on this field during process teardown.  RemoveEntryList reads
            // Flink->Blink and Blink->Flink — if either pointer is NULL it AV-crashes.
            // The field is zeroed by VadAllocateNode so we must initialise it here.
            PLIST_ENTRY pViewLinks = (PLIST_ENTRY)((ULONG_PTR)newNode +
                gSymInfo.MMVADSubsection + 3 * sizeof(PVOID));
            pViewLinks->Flink = pViewLinks;
            pViewLinks->Blink = pViewLinks;

            DbgPrint("[+] VadInsertWorkerThread: Sub=0x%p FirstPPte=0x%p LastPPte=0x%p ViewLinks=0x%p\n",
                pSub, pChainPTEs,
                (PVOID)((ULONG_PTR)pChainPTEs + (wirePages - 1) * sizeof(ULONG64)),
                pViewLinks);
        }

        // -- Step 2: commit charges ----------------------------------------
        // Mi* offsets are PDB RVAs — add NtBaseOffset to get the real VA.
        // MiInsertVadCharges can block; must run outside the lock.
        // Skip entirely for pure MEM_RESERVE nodes (SkipCharges=TRUE) — they have
        // no committed pages and no SubsectionChain, so charges would be wrong.
        // Also skip for ReuseCA nodes: charges were already applied by the original
        // VINS that allocated the CA.  Calling MiInsertVadCharges a second time on
        // the same CA re-sets the Commit bit (0x2000) in CA->LongFlags.  Even after
        // we clear it, MiInsertVadCharges may register the CA in the global pagefile
        // SharedCommitNode list.  Since Seg+0x30 (SharedCommitNode) is NULL, any
        // later MiRemoveSharedCommitNode call (e.g. from NtAlpcDeleteSectionView)
        // will dereference NULL at +0x20 and bugcheck 0x3B.
        if (gSymInfo.MiInsertVadCharges && !req->SkipCharges && !isReuseCA) {
            PFN_MiInsertVadCharges fnCharges =
                (PFN_MiInsertVadCharges)(gInit.NtBaseOffset + gSymInfo.MiInsertVadCharges);
            __try {
                status = fnCharges(newNode, pTarget);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                DbgPrint("[-] VadInsertWorkerThread: MiInsertVadCharges raised exception %08X — rolling back\n", status);
                VadFreeNode(newNode);
                if (pChainPTEs) ExFreePool(pChainPTEs);
                if (pChainSeg)  ExFreePool(pChainSeg);
                if (pChainCA)   ExFreePool(pChainCA);
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] VadInsertWorkerThread: MiInsertVadCharges failed %08X — rolling back\n", status);
                VadFreeNode(newNode);
                if (pChainPTEs) ExFreePool(pChainPTEs);
                if (pChainSeg)  ExFreePool(pChainSeg);
                if (pChainCA)   ExFreePool(pChainCA);
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }

            // Strip Commit bit (0x2000) and set Image bit (0x20) for ALL non-private nodes.
            //
            // MiRemoveSharedCommitNode+0x2c:
            //   mov eax,[rcx+38h]   ; CA->LongFlags
            //   test al,20h          ; Image bit
            //   jne +0x175           ; RETURN SAFELY if Image bit set
            //
            // Without Image bit, it walks the SharedCommitNode AVL tree rooted at
            // Seg+0x30.  Our Seg is zero-allocated, so Seg+0x30 = NULL.
            // NULL root -> sub [NULL+20h],1 -> AV bugcheck.
            //
            // Setting Image unconditionally makes MiRemoveSharedCommitNode return
            // before touching the AVL tree for any of our phantom nodes.
            // Display correctness is handled in BuildVadTypeTag: VadType is read from
            // MMVAD_FLAGS (not CA->LongFlags) so VadType==0 nodes show as "Section",
            // VadType==2 nodes show as "Image" etc., regardless of the Image CA bit.
            if (!isPrivateNode && pChainCA) {
                ULONG* pCAFlags = (ULONG*)((ULONG_PTR)pChainCA + 0x38);
                *pCAFlags = (*pCAFlags & ~0x2000u) | 0x20u;  // clear Commit, set Image
                DbgPrint("[+] VadInsertWorkerThread: CA=0x%p LongFlags=0x%08X (vadType=%lu)\n",
                    pChainCA, *pCAFlags, vadTypeVal);
            }
        }

        // -- Step 3+4: conflict check + insert under exclusive lock --------
        {
            PEX_PUSH_LOCK pLock =
                (PEX_PUSH_LOCK)((ULONG_PTR)pTarget + gSymInfo.AddressCreationLock);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(pLock);

            BOOLEAN hasConflict = FALSE;
            if (gSymInfo.MiCheckForConflictingVad) {
                PFN_MiCheckForConflictingVad fnCheck =
                    (PFN_MiCheckForConflictingVad)(gInit.NtBaseOffset + gSymInfo.MiCheckForConflictingVad);
                PVOID conflict = NULL;
                __try {
                    conflict = fnCheck(pTarget,
                        (ULONG_PTR)(req->StartingVpn << 12),
                        (ULONG_PTR)(req->EndingVpn   << 12));
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("[!] VadInsertWorkerThread: MiCheckForConflictingVad exception %08X\n",
                        GetExceptionCode());
                }
                hasConflict = (conflict != NULL);
            } else {
                PVOID* pFbRoot = (PVOID*)((ULONG_PTR)pTarget + gSymInfo.VADRoot);
                hasConflict = VadConflictWalkUnlocked(
                    (pFbRoot && MmIsAddressValid(pFbRoot)) ? *pFbRoot : NULL,
                    &gSymInfo, req->StartingVpn, req->EndingVpn);
            }

            if (hasConflict) {
                ExReleasePushLockExclusive(pLock);
                KeLeaveCriticalRegion();
                DbgPrint("[-] VadInsertWorkerThread: conflicting VAD for VPN 0x%llx-0x%llx\n",
                    req->StartingVpn, req->EndingVpn);
                if (gSymInfo.MiRemoveVadCharges) {
                    PFN_MiRemoveVadCharges fnRollback =
                        (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                    fnRollback(newNode, pTarget);
                }
                VadFreeNode(newNode);
                if (!isReuseCA) {
                    if (pChainPTEs) ExFreePool(pChainPTEs);
                    if (pChainSeg)  ExFreePool(pChainSeg);
                    if (pChainCA)   ExFreePool(pChainCA);
                }
                req->Result  = STATUS_CONFLICTING_ADDRESSES;
                req->isValid = FALSE;
                continue;
            }

            if (gSymInfo.MiInsertVad) {
                PFN_MiInsertVad fnInsert =
                    (PFN_MiInsertVad)(gInit.NtBaseOffset + gSymInfo.MiInsertVad);
                __try {
                    fnInsert(newNode, pTarget, 0);
                    status = STATUS_SUCCESS;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                    DbgPrint("[-] VadInsertWorkerThread: MiInsertVad raised exception %08X\n", status);
                }
            } else {
                ExReleasePushLockExclusive(pLock);
                KeLeaveCriticalRegion();
                status = VadTreeInsert(pTarget, &gSymInfo, newNode);
                if (!NT_SUCCESS(status)) {
                    if (gSymInfo.MiRemoveVadCharges) {
                        PFN_MiRemoveVadCharges fnRollback =
                            (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                        fnRollback(newNode, pTarget);
                    }
                    VadFreeNode(newNode);
                    if (!isReuseCA) {
                        if (pChainPTEs) ExFreePool(pChainPTEs);
                        if (pChainSeg)  ExFreePool(pChainSeg);
                        if (pChainCA)   ExFreePool(pChainCA);
                    }
                }
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }

            ExReleasePushLockExclusive(pLock);
            KeLeaveCriticalRegion();

            if (!NT_SUCCESS(status)) {
                if (gSymInfo.MiRemoveVadCharges) {
                    PFN_MiRemoveVadCharges fnRollback =
                        (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                    fnRollback(newNode, pTarget);
                }
                VadFreeNode(newNode);
                if (!isReuseCA) {
                    if (pChainPTEs) ExFreePool(pChainPTEs);
                    if (pChainSeg)  ExFreePool(pChainSeg);
                    if (pChainCA)   ExFreePool(pChainCA);
                }
                req->Result  = status;
                req->isValid = FALSE;
                continue;
            }

            // Strip Commit bit and set Image bit one final time (MiInsertVad/MiSetVadBits
            // may have re-set Commit).  See comment above for rationale.
            if (!isPrivateNode && pChainCA) {
                ULONG* pCAFlags = (ULONG*)((ULONG_PTR)pChainCA + 0x38);
                *pCAFlags = (*pCAFlags & ~0x2000u) | 0x20u;
                DbgPrint("[+] VadInsertWorkerThread: CA=0x%p LongFlags=0x%08X final (vadType=%lu)\n",
                    pChainCA, *pCAFlags, vadTypeVal);
            }
        }

        if (NT_SUCCESS(status)) {
            DbgPrint("[+] VadInsertWorkerThread: inserted node 0x%p SubChain CA=0x%p Seg=0x%p into '%s' (VPN 0x%llx-0x%llx)\n",
                newNode, pChainCA, pChainSeg, procName, req->StartingVpn, req->EndingVpn);
            DbgPrint("[+] VadInsertWorkerThread: non-private node committed via Seg->NumberOfCommittedPages\n");
            // Return the CA pointer so usermode can hand it back for cross-process map-views.
            req->ControlAreaPtr = (unsigned long long)(ULONG_PTR)pChainCA;
        } else {
            DbgPrint("[-] VadInsertWorkerThread: insert into '%s' failed %08X\n", procName, status);
        }

        req->Result  = status;
        req->isValid = FALSE;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// =================================================================
// VadRemoveWorkerThread
// Waits for hEventVAD_REMOVE. Reads a VAD_MODIFY_REQUEST with
// identifier "VREM" and calls VadTreeRemove for the given StartingVpn.
// If FreeOnRemove is set the unlinked node is also freed via VadFreeNode.
// =================================================================
VOID VadRemoveWorkerThread(PVOID Context) {
    PKEVENT          pEvent = (PKEVENT)Context;
    PVAD_MODIFY_REQUEST req;
    PEPROCESS        pTarget;
    PVOID            removed;
    NTSTATUS         status;
    UCHAR            liveWalkMode;
    const char*      procName;

    while (!g_StopRequested) {
        pEvent->Header.SignalState = 0;
        status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] VadRemoveWorkerThread: wait failed %08X\n", status);
            break;
        }

        if (!gVadModifySection) {
            DbgPrint("[-] VadRemoveWorkerThread: gVadModifySection is NULL\n");
            continue;
        }

        req = (PVAD_MODIFY_REQUEST)gVadModifySection;

        if (!req->isValid || memcmp(req->identifier, "VREM", 4) != 0) {
            DbgPrint("[-] VadRemoveWorkerThread: invalid request\n");
            continue;
        }

        // Remove from the same process whose tree was last walked
        liveWalkMode = (pInSection != NULL) ? ((PINIT)pInSection)->walkMode : 0;
        procName     = (liveWalkMode == 1) ? gInit.sourceProcess : gInit.targetProcess;
        pTarget = GetProcessByName(procName,
            gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
        if (!pTarget) {
            DbgPrint("[-] VadRemoveWorkerThread: process '%s' not found\n", procName);
            req->Result  = STATUS_NOT_FOUND;
            req->isValid = FALSE;
            continue;
        }

        removed = NULL;

        if (gSymInfo.MiRemoveVad) {
            removed = VadFindNodeByVpn(pTarget, &gSymInfo, req->StartingVpn);
            if (!removed) {
                DbgPrint("[-] VadRemoveWorkerThread: node VPN 0x%llx not found\n", req->StartingVpn);
                status = STATUS_NOT_FOUND;
            } else {
                PFN_MiRemoveVad fnRemove =
                    (PFN_MiRemoveVad)(gInit.NtBaseOffset + gSymInfo.MiRemoveVad);
                __try {
                    fnRemove(removed, pTarget);
                    status = STATUS_SUCCESS;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                    DbgPrint("[-] VadRemoveWorkerThread: MiRemoveVad raised exception %08X\n", status);
                    removed = NULL;
                }

                if (NT_SUCCESS(status) && gSymInfo.MiRemoveVadCharges) {
                    PFN_MiRemoveVadCharges fnCharges =
                        (PFN_MiRemoveVadCharges)(gInit.NtBaseOffset + gSymInfo.MiRemoveVadCharges);
                    __try {
                        fnCharges(removed, pTarget);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        DbgPrint("[!] VadRemoveWorkerThread: MiRemoveVadCharges raised exception %08X (ignored)\n",
                            GetExceptionCode());
                    }
                }
            }
        } else {
            status = VadTreeRemove(pTarget, &gSymInfo, req->StartingVpn, &removed);
        }

        if (NT_SUCCESS(status)) {
            DbgPrint("[+] VadRemoveWorkerThread: removed node 0x%p from '%s' (VPN 0x%llx)\n",
                removed, procName, req->StartingVpn);
            if (req->FreeOnRemove && removed)
                VadFreeNode(removed);
        } else {
            DbgPrint("[-] VadRemoveWorkerThread: remove from '%s' failed %08X\n", procName, status);
        }

        req->Result  = status;
        req->isValid = FALSE;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
