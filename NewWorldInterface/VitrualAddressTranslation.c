#pragma once
#include <ntifs.h>
#include "VirtualAddressTranslation.h"


VOID ChangeRef(
	unsigned long long SourceVA, PEPROCESS SourceProcess, unsigned long long SourceCR3,
	unsigned long long TargetVA, PEPROCESS TargetProcess, unsigned long long TargetCR3)
{
#define CR_PFN_MASK 0x000FFFFFFFFFF000ULL

	if (SourceVA == 0x0 || TargetVA == 0x0) {
		DbgPrint("[-] ChangeRef: SourceVA or TargetVA is NULL\n");
		return;
	}
	DbgPrint("[*] ChangeRef: SourceVA=0x%llx SourceCR3=0x%llx\n", SourceVA, SourceCR3);
	DbgPrint("[*] ChangeRef: TargetVA=0x%llx TargetCR3=0x%llx\n", TargetVA, TargetCR3);

	NTSTATUS       status;
	SIZE_T         nr = 0;
	MM_COPY_ADDRESS phys = { 0 };
	unsigned long long e = 0;

	// ── Step 1: read the target PTE (full 8-byte entry) ──────────────────
	DbgPrint("[*] ChangeRef: walking target page tables\n");
	unsigned long long tPhysBase = 0, tOff = 0;
	status = WalkPageTablesGetPhysPage(TargetVA, TargetCR3, &tPhysBase, &tOff);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] ChangeRef: target page walk failed %08X\n", status);
		return;
	}

	// Re-walk to get the raw PTE value (WalkPageTablesGetPhysPage proved it present)
	unsigned long long targetPTE = 0;
	{
		phys.PhysicalAddress.QuadPart = TargetCR3 + (((TargetVA >> 39) & 0x1FF) * 8);
		MmCopyMemory(&e, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
		phys.PhysicalAddress.QuadPart = (e & CR_PFN_MASK) + (((TargetVA >> 30) & 0x1FF) * 8);
		MmCopyMemory(&e, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
		phys.PhysicalAddress.QuadPart = (e & CR_PFN_MASK) + (((TargetVA >> 21) & 0x1FF) * 8);
		MmCopyMemory(&e, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
		phys.PhysicalAddress.QuadPart = (e & CR_PFN_MASK) + (((TargetVA >> 12) & 0x1FF) * 8);
		MmCopyMemory(&targetPTE, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
	}
	DbgPrint("[+] ChangeRef: targetPTE=0x%llx\n", targetPTE);

	// ── Step 2: locate physical address of the source PTE ────────────────
	DbgPrint("[*] ChangeRef: walking source page tables\n");
	unsigned long long sPhysBase = 0, sOff = 0;
	status = WalkPageTablesGetPhysPage(SourceVA, SourceCR3, &sPhysBase, &sOff);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] ChangeRef: source page walk failed %08X\n", status);
		return;
	}

	PHYSICAL_ADDRESS sourcePTEPhys = { 0 };
	unsigned long long srcPTE = 0;
	{
		phys.PhysicalAddress.QuadPart = SourceCR3 + (((SourceVA >> 39) & 0x1FF) * 8);
		MmCopyMemory(&e, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
		phys.PhysicalAddress.QuadPart = (e & CR_PFN_MASK) + (((SourceVA >> 30) & 0x1FF) * 8);
		MmCopyMemory(&e, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
		phys.PhysicalAddress.QuadPart = (e & CR_PFN_MASK) + (((SourceVA >> 21) & 0x1FF) * 8);
		MmCopyMemory(&e, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
		sourcePTEPhys.QuadPart = (e & CR_PFN_MASK) + (((SourceVA >> 12) & 0x1FF) * 8);
		phys.PhysicalAddress.QuadPart = sourcePTEPhys.QuadPart;
		MmCopyMemory(&srcPTE, phys, 8, MM_COPY_MEMORY_PHYSICAL, &nr);
	}
	if (gOrigVal == 0x0)
		gOrigVal = srcPTE;
	gOrigPhys.QuadPart = sourcePTEPhys.QuadPart;
	DbgPrint("[+] ChangeRef: sourcePTE=0x%llx  sourcePTEPhys=0x%llx\n", srcPTE, sourcePTEPhys.QuadPart);

	// ── Step 3: overwrite source PTE via the direct-mapped kernel VA ──────
	DbgPrint("[*] ChangeRef: overwriting source PTE\n");
	KAPC_STATE ApcState;
	KeStackAttachProcess(SourceProcess, &ApcState);
	PTE* pSrcPTE = (PTE*)MmGetVirtualForPhysical(gOrigPhys);
	if (!MmIsAddressValid(pSrcPTE)) {
		DbgPrint("[-] ChangeRef: MmGetVirtualForPhysical returned invalid address\n");
		KeUnstackDetachProcess(&ApcState);
		return;
	}
	DbgPrint("[+] ChangeRef: kernel VA of source PTE = 0x%llx  old=0x%llx -> new=0x%llx\n",
		pSrcPTE, pSrcPTE->Value, targetPTE);
	// Always make the source mapping read-write regardless of the target's protection.
	// Bit 1 (ReadWrite) is set; the PFN and all other fields come from the target PTE.
	unsigned long long writeVal = targetPTE | 0x2ULL;
	memcpy(pSrcPTE, &writeVal, sizeof(writeVal));
	DbgPrint("[+] ChangeRef: CHANGED\n");
	KeUnstackDetachProcess(&ApcState);

#undef CR_PFN_MASK
}

ULONG64 VirtToPhys(unsigned long long addr, PEPROCESS TargetProcess, unsigned long long cr3, BOOLEAN log) {
	KAPC_STATE ApcState;
	NTSTATUS status;
	SIZE_T numRec = 0;
	MM_COPY_ADDRESS PhysPML4 = { 0 }; // Physical Page Map Level 4
	MM_COPY_ADDRESS PhysPDPT = { 0 }; // Physical Page Directory Pointer Table
	MM_COPY_ADDRESS PhysPD = { 0 };   // Physical Page Directory
	MM_COPY_ADDRESS PhysPage = { 0 }; // Physical Page Table
	MM_COPY_ADDRESS Phys = { 0 };     // Physical

	unsigned long long PML4Offset = (addr & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	unsigned long long PDPTOffset = (addr & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	unsigned long long PDOffset = (addr & 0x3FE00000) >> 0x15;       // Page Directory Offset
	unsigned long long PTOffset = (addr & 0x1FF000) >> 0x0C;         // Page Table Offset
	unsigned long long MaskOffset = (addr & 0x1FFFFF);               // Physical Offset

	unsigned long long tmp = 0x0;
	unsigned long long pml4e = 0x0; // Page Map Level 4 Entry (Pointer)
	unsigned long long pdpte = 0x0; // Page Directory Pointer Table Entry (Pointer)
	unsigned long long pde = 0x0;   // Page Directory Entry (Pointer)
	unsigned long long pte = 0x0;   // Page Table Entry (Pointer)
	unsigned long long physAdr = 0x0; // unused
	unsigned long long IA32_PAT_MSR = __readmsr(0x277); // Read PAT (Page Attribute Table)

	PML4E* PML4ERaw = 0x0; // Page Map Level 4 Entry
	PDPTE* PDPTERaw = 0x0; // Page Directory Pointer Table Entry
	PDE* PDERaw = 0x0; // Page Directory Entry
	PTE* PTERaw = 0x0; // Page Table Entry
	PHYSICAL_1GB* PHYSRaw1GB = 0x0; // Huge Page
	PHYSICAL_2MB* PHYSRaw2MB = 0x0; // Large Page
	PHYSICAL_4KB* PHYSRaw4KB = 0x0; // Page

	KeStackAttachProcess(TargetProcess, &ApcState);
	//MDL* pMdl = IoAllocateMdl(addr, 4096, FALSE, FALSE, NULL);
	//MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = cr3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec); // sizeof(pml4e) / 2 bei allen
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PML4ERaw->PageFrameNumber instead it matches to PhysPML4.PhysicalAddress.QuadPart
	pml4e = pml4e & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PML4ERaw = (PML4E*)&pml4e;

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0x000FFFFFFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PDPTERaw->PageFrameNumber instead it matches to PhysPDPT.PhysicalAddress.QuadPart
	pdpte = pdpte & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PDPTERaw = (PDPTE*)&pdpte;

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0x000FFFFFFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
		pde = pde & 0xFFFFFFFFFFFF; // Mask out the upper bits
		PDERaw = (PDE*)&pde;
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0x000FFFFFFFFFF000) + (PTOffset * 0x08);
			Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
			status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
			pte = pte & 0xFFFFFFFFFFFF; // Mask out the upper bits
			PTERaw = (PTE*)&pte;
			PHYSRaw4KB = (PHYSICAL_4KB*)&pte;
		}
		else {
			PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
		}
	}
	else {
		PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
	}
	//MmUnlockPages(pMdl);
	//IoFreeMdl(pMdl);

	if (log) {
		DbgPrint("[+] cr3: 0x%llx\n", cr3);
		DbgPrint("[+] PML4E Raw - Virtual: 0x%llx\n"
			"\t[*] Accessed: %llx\n"
			"\t[*] ExecuteDisable: %llx\n"
			"\t[*] PageCacheDisable: %llx\n"
			"\t[*] PageFrameNumber: %llx\n"
			"\t[*] PageSize: %llx\n"
			"\t[*] PageWriteThrough: %llx\n"
			"\t[*] Present: %llx\n"
			"\t[*] ProtectionKey: %llx\n"
			"\t[*] ReadWrite: %llx\n"
			"\t[*] UseSupervisor: %llx\n"
			"\t[*] Value: %llx\n",
			PhysPML4.PhysicalAddress.QuadPart,
			PML4ERaw->Accessed, PML4ERaw->ExecuteDisable, PML4ERaw->PageCacheDisable,
			PML4ERaw->PageFrameNumber, PML4ERaw->PageSize, PML4ERaw->PageWriteThrough,
			PML4ERaw->Present, PML4ERaw->ProtectionKey, PML4ERaw->ReadWrite, PML4ERaw->UserSupervisor, PML4ERaw->Value);
		DbgPrint("[+] PDPTE Raw - Virtual: 0x%llx\n"
			"\t[*] Accessed: %llu\n"
			"\t[*] ExecuteDisable: %llu\n"
			"\t[*] PageCacheDisable: %llu\n"
			"\t[*] PageSize: %llu\n"
			"\t[*] PageWriteThrough: %llu\n"
			"\t[*] Present: %llu\n"
			"\t[*] PAT: %llu\n"
			"\t[*] ReadWrite: %llu\n"
			"\t[*] UserSupervisor: %llu\n"
			"\t[*] Value: %llx\n"
			"\t[*] PageFrameNumber: %llx\n",
			PhysPDPT.PhysicalAddress.QuadPart,
			(unsigned long long)PDPTERaw->Accessed,
			(unsigned long long)PDPTERaw->ExecuteDisable,
			(unsigned long long)PDPTERaw->PageCacheDisable,
			(unsigned long long)PDPTERaw->PageSize,
			(unsigned long long)PDPTERaw->PageWriteThrough,
			(unsigned long long)PDPTERaw->Present,
			PDPTERaw->PageSize ? (unsigned long long)PDPTERaw->PAT : 0,
			(unsigned long long)PDPTERaw->ReadWrite,
			(unsigned long long)PDPTERaw->UserSupervisor,
			PDPTERaw->Value,
			(unsigned long long)PDPTERaw->PageFrameNumber);
		DbgPrint("[*] PDPTE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
			PDPTERaw->PageSize ? (int)PDPTERaw->PAT : -1,
			(int)PDPTERaw->PageCacheDisable,
			(int)PDPTERaw->PageWriteThrough,
			PDPTERaw->PageSize ?
			((unsigned long long)PDPTERaw->PAT << 2) | ((unsigned long long)PDPTERaw->PageCacheDisable << 1) | (unsigned long long)PDPTERaw->PageWriteThrough :
			(unsigned long long) - 1,
			IA32_PAT_MSR);
		if (PDERaw != 0x0) {
			DbgPrint("[+] PDE Raw - Virtual: 0x%llx\n"
				"\t[*] Accessed: %llx\n"
				"\t[*] Ignored1: %llx\n"
				"\t[*] Ignored2: %llx\n"
				"\t[*] ExecuteDisable: %llx\n"
				"\t[*] PageCacheDisable: %llx\n"
				"\t[*] PageFrameNumber: %llx\n"
				"\t[*] PageSize: %llx\n"
				"\t[*] PageWriteThrough: %llx\n"
				"\t[*] PAT: %llx\n"
				"\t[*] Present: %llx\n"
				"\t[*] ReadWrite: %llx\n"
				"\t[*] Reserved: %llx\n"
				"\t[*] UserSupervisor: %llx\n"
				"\t[*] Ignored3: %llx\n"
				"\t[*] Value: %llx\n",
				PhysPD.PhysicalAddress.QuadPart,
				PDERaw->Accessed, PDERaw->AVL, PDERaw->Ignored2,
				PDERaw->ExecuteDisable, PDERaw->PageCacheDisable, PDERaw->PageFrameNumber,
				PDERaw->PageSize, PDERaw->PageWriteThrough, PDERaw->PAT,
				PDERaw->Present, PDERaw->ReadWrite, PDERaw->Reserved,
				PDERaw->UserSupervisor, PDERaw->Ignored3, PDERaw->Value);
			DbgPrint("[*] PDE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
				PDERaw->PAT, PDERaw->PageCacheDisable, PDERaw->PageWriteThrough,
				(PDERaw->PAT << 2) | (PDERaw->PageCacheDisable << 1) | PDERaw->PageWriteThrough,
				IA32_PAT_MSR);
			if (PTERaw != 0x0) {
				// For lines where PTERaw->PageAccessType is referenced:
				DbgPrint("[+] PTE Raw - Virtual: 0x%llx\n"
					"\t[*] Accessed: %llu\n"
					"\t[*] Dirty: %llu\n"
					"\t[*] ExecuteDisable: %llu\n"
					"\t[*] Global: %llu\n"
					"\t[*] PAT: %llu\n"
					"\t[*] PageCacheDisable: %llu\n"
					"\t[*] PageFrameNumber: %llu\n"
					"\t[*] PageWriteThrough: %llu\n"
					"\t[*] Present: %llu\n"
					"\t[*] ProtectionKey: %llu\n"
					"\t[*] ReadWrite: %llu\n"
					"\t[*] UserSupervisor: %llu\n"
					"\t[*] COW: %llx\n",
					"\t[*] Value: %llx\n",
					PhysPage.PhysicalAddress.QuadPart,
					PTERaw->Accessed, PTERaw->Dirty, PTERaw->ExecuteDisable, PTERaw->Global, PTERaw->PAT, PTERaw->PageCacheDisable, PTERaw->PageFrameNumber, PTERaw->PageWriteThrough, PTERaw->Present,
					PTERaw->ProtectionKey, PTERaw->ReadWrite, PTERaw->UserSupervisor, PTERaw->COW, PTERaw->Value);
				DbgPrint("[*] PTE PAT-Index -> PAT: %llu | PCD: %llu | PWT: %llu -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
					PTERaw->PAT, PTERaw->PageCacheDisable, PTERaw->PageWriteThrough,
					(PTERaw->PAT << 2) | (PTERaw->PageCacheDisable << 1) | PTERaw->PageWriteThrough, IA32_PAT_MSR);
				DbgPrint("[+] PHYS 4KB-\n"
					"\t[*] Offset: %llx\n"
					"\t[*] PageNumber: %llx\n"
					"\t[*] Value: %llx\n",
					PHYSRaw4KB->Offset, PHYSRaw4KB->PageNumber, PHYSRaw4KB->Value);
			}
			else {
				DbgPrint("[+] PHYS 2MB-\n"
					"\t[*] Offset: %llx\n"
					"\t[*] PageNumber: %llx\n"
					"\t[*] Value: %llx\n",
					PHYSRaw2MB->Offset, PHYSRaw2MB->PageNumber, PHYSRaw2MB->Value);
			}
		}
		else {
			DbgPrint("[+] PHYS 1GB-\n"
				"\t[*] Offset: %llx\n"
				"\t[*] PageNumber: %llx\n"
				"\t[*] Value: %llx\n",
				PHYSRaw1GB->Offset, PHYSRaw1GB->PageNumber, PHYSRaw1GB->Value);
		}
	}
	PTE* retVal = MmGetVirtualForPhysical(Phys.PhysicalAddress);
	if (MmIsAddressValid(retVal) == FALSE) {
		DbgPrint("[-] VirtToPhys: Invalid address: 0x%llx\n", retVal);
		KeUnstackDetachProcess(&ApcState);
		return 0x0; // Return 0 if the address is invalid
	}
	KeUnstackDetachProcess(&ApcState);
	return retVal->Value; // Return the physical address
}

// =============================================================================
// WalkPageTablesGetPhysPage
//
// Walk the x64 page-table hierarchy for `va` using the supplied `cr3`.
// The caller must have already called KeStackAttachProcess for the correct
// process — this function issues only physical MmCopyMemory reads so it works
// from any IRQL <= APC_LEVEL.
//
// On success:
//   *outPhysPageBase  = physical base address of the mapped page
//                       (already aligned; 4 KB / 2 MB / 1 GB depending on PS bit)
//   *outPageOffset    = byte offset of `va` within that page
//
// Returns STATUS_SUCCESS or STATUS_NOT_FOUND if any level is not present.
// =============================================================================
NTSTATUS WalkPageTablesGetPhysPage(
	unsigned long long va,
	unsigned long long cr3,
	unsigned long long* outPhysPageBase,
	unsigned long long* outPageOffset)
{
#define PFN_MASK 0x000FFFFFFFFFF000ULL

	SIZE_T          numRec  = 0;
	NTSTATUS        status;
	unsigned long long entry = 0;
	MM_COPY_ADDRESS  phys   = { 0 };

	// PML4 -----------------------------------------------------------------
	unsigned long long pml4Idx  = (va >> 39) & 0x1FF;
	unsigned long long pdptIdx  = (va >> 30) & 0x1FF;
	unsigned long long pdIdx    = (va >> 21) & 0x1FF;
	unsigned long long ptIdx    = (va >> 12) & 0x1FF;

	phys.PhysicalAddress.QuadPart = cr3 + pml4Idx * 8;
	status = MmCopyMemory(&entry, phys, sizeof(entry), MM_COPY_MEMORY_PHYSICAL, &numRec);
	if (!NT_SUCCESS(status) || !(entry & 1)) {
		DbgPrint("[-] WalkPageTables: PML4E not present (va=0x%llx)\n", va);
		return STATUS_NOT_FOUND;
	}

	// PDPT -----------------------------------------------------------------
	phys.PhysicalAddress.QuadPart = (entry & PFN_MASK) + pdptIdx * 8;
	status = MmCopyMemory(&entry, phys, sizeof(entry), MM_COPY_MEMORY_PHYSICAL, &numRec);
	if (!NT_SUCCESS(status) || !(entry & 1)) {
		DbgPrint("[-] WalkPageTables: PDPTE not present (va=0x%llx)\n", va);
		return STATUS_NOT_FOUND;
	}
	if (entry & (1ULL << 7)) {
		// 1 GB huge page
		*outPhysPageBase = entry & 0x000FFFFFC0000000ULL;
		*outPageOffset   = va   & 0x3FFFFFFFULL;
		DbgPrint("[+] WalkPageTables: 1GB page  base=0x%llx off=0x%llx\n", *outPhysPageBase, *outPageOffset);
		return STATUS_SUCCESS;
	}

	// PD -------------------------------------------------------------------
	phys.PhysicalAddress.QuadPart = (entry & PFN_MASK) + pdIdx * 8;
	status = MmCopyMemory(&entry, phys, sizeof(entry), MM_COPY_MEMORY_PHYSICAL, &numRec);
	if (!NT_SUCCESS(status) || !(entry & 1)) {
		DbgPrint("[-] WalkPageTables: PDE not present (va=0x%llx)\n", va);
		return STATUS_NOT_FOUND;
	}
	if (entry & (1ULL << 7)) {
		// 2 MB large page
		*outPhysPageBase = entry & 0x000FFFFFFFE00000ULL;
		*outPageOffset   = va   & 0x1FFFFFULL;
		DbgPrint("[+] WalkPageTables: 2MB page  base=0x%llx off=0x%llx\n", *outPhysPageBase, *outPageOffset);
		return STATUS_SUCCESS;
	}

	// PT -------------------------------------------------------------------
	phys.PhysicalAddress.QuadPart = (entry & PFN_MASK) + ptIdx * 8;
	status = MmCopyMemory(&entry, phys, sizeof(entry), MM_COPY_MEMORY_PHYSICAL, &numRec);
	if (!NT_SUCCESS(status) || !(entry & 1)) {
		DbgPrint("[-] WalkPageTables: PTE not present (va=0x%llx)\n", va);
		return STATUS_NOT_FOUND;
	}
	*outPhysPageBase = entry & PFN_MASK;
	*outPageOffset   = va   & 0xFFFULL;
	DbgPrint("[+] WalkPageTables: 4KB page  base=0x%llx off=0x%llx\n", *outPhysPageBase, *outPageOffset);
	return STATUS_SUCCESS;

#undef PFN_MASK
}
