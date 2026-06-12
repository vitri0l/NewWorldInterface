#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")
#include <vector>
#include <tchar.h>
#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <chrono>
#include <conio.h>
#include <unordered_map>
#include <tlhelp32.h>
#include "SharedDefs.h"
#include "Globals.h"
#include "Commands.h"
#include "UI.h"
// -----------------------------------------------------------------
// =================================================================
// GLOBAL VARIABLES
// =================================================================
size_t totalAllocationSize;
size_t totalCopiedSize;

PVOID SymbolsArray;
static int SymbolsArrayIndex = 0;
size_t SymbolsArrayAllocationSize = 0;
// -----------------------------------------------------------------

typedef struct PE_relocation_t {
	DWORD RVA;
	WORD Type : 4;
} PE_relocation;

typedef struct PE_codeview_debug_info_t {
	DWORD signature;
	GUID guid;
	DWORD age;
	CHAR pdbName[1];
} PE_codeview_debug_info;

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	PVOID baseAddress;
	//headers ptrs
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optHeader;
	IMAGE_DATA_DIRECTORY* dataDir;
	IMAGE_SECTION_HEADER* sectionHeaders;
	//export info
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	LPDWORD exportedNames;
	DWORD exportedNamesLength;
	LPDWORD exportedFunctions;
	LPWORD exportedOrdinals;
	//relocations info
	DWORD nbRelocations;
	PE_relocation* relocations;
	//debug info
	IMAGE_DEBUG_DIRECTORY* debugDirectory;
	PE_codeview_debug_info* codeviewDebugInfo;
} PE;

typedef struct symbol_ctx_t {
	LPWSTR pdb_name_w;
	DWORD64 pdb_base_addr;
	HANDLE sym_handle;
} symbol_ctx;

// -----------------------------------------------------------------
// Global bitfield layout definitions (types declared in Globals.h)
BITFIELD_LAYOUT g_MmVadFlags     = {};
BITFIELD_LAYOUT g_MmVadFlags1    = {};
BITFIELD_LAYOUT g_MmVadFlags2    = {};
BITFIELD_LAYOUT g_MmSectionFlags = {};
// -----------------------------------------------------------------

PBYTE ReadFullFileW(LPCWSTR fileName) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	PBYTE fileContent = (PBYTE)malloc(fileSize); // cast
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		free(fileContent);
		fileContent = NULL;
	}
	CloseHandle(hFile);
	return fileContent;
}

IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
	IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
	for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
		DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
		DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
		if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
			return &sectionHeaders[sectionIndex];
		}
	}
	return NULL;
}

PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
	PVOID peBase = pe->dosHeader;
	if (pe->isMemoryMapped) {
		return (PBYTE)peBase + rva;
	}

	IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
	if (NULL == rvaSectionHeader) {
		return NULL;
	}
	else {
		return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
	}
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
	PE* pe = (PE*)calloc(1, sizeof(PE));
	if (NULL == pe) {
		exit(1);
	}
	pe->isMemoryMapped = isMemoryMapped;
	pe->isInAnotherAddressSpace = FALSE;
	pe->hProcess = INVALID_HANDLE_VALUE;
	pe->dosHeader = (IMAGE_DOS_HEADER*)imageBase; // cast
	pe->ntHeader = (IMAGE_NT_HEADERS*)(((PBYTE)imageBase) + pe->dosHeader->e_lfanew);
	pe->optHeader = &pe->ntHeader->OptionalHeader;
	if (isMemoryMapped) {
		pe->baseAddress = imageBase;
	}
	else {
		pe->baseAddress = (PVOID)pe->optHeader->ImageBase;
	}
	pe->dataDir = pe->optHeader->DataDirectory;
	pe->sectionHeaders = (IMAGE_SECTION_HEADER*)(((PBYTE)pe->optHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);
	DWORD exportRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRVA == 0) {
		pe->exportDirectory = NULL;
		pe->exportedNames = NULL;
		pe->exportedFunctions = NULL;
		pe->exportedOrdinals = NULL;
	}
	else {
		pe->exportDirectory = (IMAGE_EXPORT_DIRECTORY*)PE_RVA_to_Addr(pe, exportRVA);
		pe->exportedNames = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNames);
		pe->exportedFunctions = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfFunctions);
		pe->exportedOrdinals = (LPWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNameOrdinals);
		pe->exportedNamesLength = pe->exportDirectory->NumberOfNames;
	}
	pe->relocations = NULL;
	DWORD debugRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	if (debugRVA == 0) {
		pe->debugDirectory = NULL;
	}
	else {
		pe->debugDirectory = (IMAGE_DEBUG_DIRECTORY*)PE_RVA_to_Addr(pe, debugRVA);
		if (pe->debugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
			pe->debugDirectory = NULL;
		}
		else {
			pe->codeviewDebugInfo = (PE_codeview_debug_info*)PE_RVA_to_Addr(pe, pe->debugDirectory->AddressOfRawData);
			if (pe->codeviewDebugInfo->signature != *((DWORD*)"RSDS")) {
				pe->debugDirectory = NULL;
				pe->codeviewDebugInfo = NULL;
			}
		}
	}
	return pe;
}

VOID PE_destroy(PE* pe)
{
	if (pe->relocations) {
		free(pe->relocations);
		pe->relocations = NULL;
	}
	free(pe);
}

BOOL FileExistsW(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
	CloseHandle(hFile);
	return res;
}

BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size) {
	///wprintf_or_not(L"Downloading https://%s%s...\n", domain, uri);
	// Get proxy configuration
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
	WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
	BOOL proxySet = !(proxyConfig.fAutoDetect || proxyConfig.lpszAutoConfigUrl != NULL);
	DWORD proxyAccessType = proxySet ? ((proxyConfig.lpszProxy == NULL) ?
		WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY) : WINHTTP_ACCESS_TYPE_NO_PROXY;
	LPCWSTR proxyName = proxySet ? proxyConfig.lpszProxy : WINHTTP_NO_PROXY_NAME;
	LPCWSTR proxyBypass = proxySet ? proxyConfig.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS;

	// Initialize HTTP session and request
	HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.0", proxyAccessType, proxyName, proxyBypass, 0);
	if (hSession == NULL) {
		printf("WinHttpOpen failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (!hConnect) {
		printf("WinHttpConnect failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uri, NULL,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		return FALSE;
	}

	// Configure proxy manually
	if (!proxySet)
	{
		WINHTTP_AUTOPROXY_OPTIONS  autoProxyOptions;
		autoProxyOptions.dwFlags = proxyConfig.lpszAutoConfigUrl != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : WINHTTP_AUTOPROXY_AUTO_DETECT;
		autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
		autoProxyOptions.fAutoLogonIfChallenged = TRUE;

		if (proxyConfig.lpszAutoConfigUrl != NULL)
			autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;

		WCHAR szUrl[MAX_PATH] = { 0 };
		swprintf_s(szUrl, _countof(szUrl), L"https://%ws%ws", domain, uri);

		WINHTTP_PROXY_INFO proxyInfo;
		WinHttpGetProxyForUrl(
			hSession,
			szUrl,
			&autoProxyOptions,
			&proxyInfo);

		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
		DWORD logonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &logonPolicy, sizeof(logonPolicy));
	}

	// Perform request
	BOOL bRequestSent;
	do {
		bRequestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	} while (!bRequestSent && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
	if (!bRequestSent) {
		return FALSE;
	}
	BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResponseReceived) {
		return FALSE;
	}

	// Read response
	DWORD dwAvailableSize = 0;
	DWORD dwDownloadedSize = 0;
	SIZE_T allocatedSize = 4096;
	if (!WinHttpQueryDataAvailable(hRequest, &dwAvailableSize))
	{
		return FALSE;
	}
	*output = (PBYTE)malloc(allocatedSize);
	*output_size = 0;
	while (dwAvailableSize)
	{
		while (*output_size + dwAvailableSize > allocatedSize) {
			allocatedSize *= 2;
			PBYTE new_output = (PBYTE)realloc(*output, allocatedSize);
			if (new_output == NULL)
			{
				return FALSE;
			}
			*output = new_output;
		}
		if (!WinHttpReadData(hRequest, *output + *output_size, dwAvailableSize, &dwDownloadedSize))
		{
			return FALSE;
		}
		*output_size += dwDownloadedSize;

		WinHttpQueryDataAvailable(hRequest, &dwAvailableSize);
	}
	PBYTE new_output = (PBYTE)realloc(*output, *output_size);
	if (new_output == NULL)
	{
		return FALSE;
	}
	*output = new_output;
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return TRUE;
}

BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
	WCHAR pdb_name_w[MAX_PATH] = { 0 };
	GUID guid = image_pe->codeviewDebugInfo->guid;
	DWORD age = image_pe->codeviewDebugInfo->age;
	MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
	return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

symbol_ctx* LoadSymbolsFromPE(PE* pe) {
	symbol_ctx* ctx = (symbol_ctx*)calloc(1, sizeof(symbol_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
	ctx->pdb_name_w = (LPWSTR)calloc(size_needed, sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
	if (!FileExistsW(ctx->pdb_name_w)) {
		printf("Symbol file does not exist!\n");
		return NULL;
		PBYTE file;
		SIZE_T file_size;
		BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
		if (!res) {
			free(ctx);
			return NULL;
		}
		WriteFullFileW(ctx->pdb_name_w, file, file_size);
		free(file);
	}
	else {
		//TODO : check if exisiting PDB corresponds to the file version
	}
	DWORD64 asked_pdb_base_addr = 0x140000000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	//DWORD64 asked_pdb_base_addr = 0x1337000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	//DWORD64 asked_pdb_base_addr = 0x1c0000000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	DWORD pdb_image_size = MAXDWORD;
	HANDLE cp = GetCurrentProcess();
	//if (!SymInitialize(cp, NULL, FALSE)) {
	if (!SymInitializeW(cp, ctx->pdb_name_w, FALSE)) {
		//if (!SymInitializeW(cp, ctx->pdb_name_w, FALSE)) {
		printf("[-] Failed SymInitialize\n");
		free(ctx);
		return NULL;
	}
	ctx->sym_handle = cp;

	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	DWORD64 addr = (DWORD64)pe->baseAddress;
	//addr -= 0x13ECC9000;
	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, addr, pdb_image_size, NULL, 0);

	//printf("tmp\n");
	while (pdb_base_addr == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SUCCESS)
			printf("[+] Success\n");
		break;
		if (err == ERROR_FILE_NOT_FOUND) {
			printf("[-] PDB file not found\n");
			SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
			SymCleanup(cp);
			free(ctx);
			return NULL;
		}
		asked_pdb_base_addr += 0x100000;
		//pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
		pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	}
	ctx->pdb_base_addr = pdb_base_addr;

	return ctx;
}

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
	PVOID image_content = ReadFullFileW(image_file_path);
	PE* pe = PE_create(image_content, FALSE);
	symbol_ctx* ctx = LoadSymbolsFromPE(pe);
	PE_destroy(pe);
	free(image_content);
	return ctx;
}

DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
	if (!res) {
		DWORD err = GetLastError();
		printf("[-] SymGetTypeFromName failed: sym_handle: 0x%llx, pdb_base_addr: 0x%llx, struct_name: %s, Err: %d\n", ctx->sym_handle, ctx->pdb_base_addr, struct_name, err);
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = (TI_FINDCHILDREN_PARAMS*)calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		printf("[-] calloc failed\n");
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res) {
		printf("[-] SymGetTypeInfo failed\n");
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = (TI_FINDCHILDREN_PARAMS*)realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		printf("[-] realloc failed\n");
		free(childrenParam);
		return 0;
	}
	childrenParam = ptr;
	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
	DWORD offset = 0;
	for (ULONG i = 0; i < childrenParam->Count; i++) {
		ULONG childID = childrenParam->ChildId[i];
		WCHAR* name = NULL;
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
		if (wcscmp(field_name, name)) {
			continue;
		}
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
		break;
	}
	free(childrenParam);
	return offset;
}

DWORD GetTypeSize(symbol_ctx* ctx, LPCSTR type_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen   = sizeof(si.name);
	if (!SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, type_name, &si.si))
		return 0;
	ULONG64 sz = 0;
	SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_LENGTH, &sz);
	return (DWORD)sz;
}

// Enumerate all members of a struct/union from the PDB
// bit-position and bit-length for each.  Returns the number of members found.
// pOut must point to a buffer of at least maxOut BITFIELD_MEMBER entries.
// Helper: enumerate bitfield members from a type ID, recursing into anonymous nested UDTs.
// In PDB, all direct children of a struct/union are SymTagData.
// An anonymous inner struct is a SymTagData child whose *type* is SymTagUDT — we recurse into it.
static DWORD EnumBitfieldMembersById(HANDLE symHandle, DWORD64 base,
	DWORD typeId, DWORD byteBase,
	BITFIELD_MEMBER* pOut, DWORD maxOut) {

	DWORD count = 0;
	if (!SymGetTypeInfo(symHandle, base, typeId, TI_GET_CHILDRENCOUNT, &count) || count == 0)
		return 0;

	TI_FINDCHILDREN_PARAMS* cp = (TI_FINDCHILDREN_PARAMS*)calloc(
		1, sizeof(TI_FINDCHILDREN_PARAMS) + count * sizeof(ULONG));
	if (!cp) return 0;
	cp->Count = count;
	SymGetTypeInfo(symHandle, base, typeId, TI_FINDCHILDREN, cp);

	DWORD found = 0;
	for (DWORD i = 0; i < count && found < maxOut; i++) {
		ULONG id = cp->ChildId[i];

		// Get the type of this child member
		DWORD childTypeId = 0;
		SymGetTypeInfo(symHandle, base, id, TI_GET_TYPE, &childTypeId);

		// Check if the child's type is a UDT (anonymous nested struct/union)
		DWORD typeTag = 0;
		if (childTypeId)
			SymGetTypeInfo(symHandle, base, childTypeId, TI_GET_SYMTAG, &typeTag);

		if (typeTag == 11 /* SymTagUDT */) {
			// Anonymous nested struct/union — get its byte offset and recurse into its type
			DWORD nestedByteOffset = 0;
			SymGetTypeInfo(symHandle, base, id, TI_GET_OFFSET, &nestedByteOffset);
			DWORD sub = EnumBitfieldMembersById(symHandle, base, childTypeId,
				byteBase + nestedByteOffset, pOut + found, maxOut - found);
			found += sub;
		} else {
			// Regular member (bitfield or plain field) — record it
			WCHAR* wname = NULL;
			SymGetTypeInfo(symHandle, base, id, TI_GET_SYMNAME, &wname);
			if (!wname) continue;

			DWORD memberByteOffset = 0, bitPos = 0;
			ULONGLONG bitLen = 0;
			SymGetTypeInfo(symHandle, base, id, TI_GET_OFFSET,      &memberByteOffset);
			SymGetTypeInfo(symHandle, base, id, TI_GET_BITPOSITION, &bitPos);
			SymGetTypeInfo(symHandle, base, id, TI_GET_LENGTH,      &bitLen);

			WideCharToMultiByte(CP_UTF8, 0, wname, -1,
				pOut[found].name, (int)sizeof(pOut[found].name), NULL, NULL);
			pOut[found].bitPos = (byteBase + memberByteOffset) * 8 + bitPos;
			pOut[found].bitLen = (DWORD)bitLen;
			LocalFree(wname);
			found++;
		}
	}
	free(cp);
	return found;
}

DWORD GetBitfieldMembers(symbol_ctx* ctx, LPCSTR struct_name,
	BITFIELD_MEMBER* pOut, DWORD maxOut) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen   = sizeof(si.name);
	if (!SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si)) {
		printf("[-] GetBitfieldMembers: SymGetTypeFromName failed for '%s': %d\n",
			struct_name, GetLastError());
		return 0;
	}
	DWORD found = EnumBitfieldMembersById(ctx->sym_handle, ctx->pdb_base_addr,
		si.si.TypeIndex, 0, pOut, maxOut);
	if (found == 0)
		printf("[-] GetBitfieldMembers: no members found for '%s'\n", struct_name);
	return found;
}

void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	if (ctx == NULL) {
		return;
	}

	if (ctx->sym_handle != NULL && ctx->pdb_base_addr != 0) {
		// Only unload this specific module
		if (!SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr)) {
			printf("[-] SymUnloadModule failed: %d\n", GetLastError());
		}

		// Don't call SymCleanup here - it terminates the symbol handler
		// SymCleanup should only be called when you're completely done with symbols
	}

	// Delete the PDB file if requested
	if (delete_pdb && ctx->pdb_name_w != NULL) {
		DeleteFileW(ctx->pdb_name_w);
	}

	// Free allocated memory
	if (ctx->pdb_name_w != NULL) {
		free(ctx->pdb_name_w);
		ctx->pdb_name_w = NULL;
	}

	// Free the context structure itself
	free(ctx);
}
void CleanupSymbolHandler(HANDLE symHandle) {
	if (symHandle != NULL) {
		if (!SymCleanup(symHandle)) {
			printf("[-] SymCleanup failed: %d\n", GetLastError());
		}
	}
}
DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO symbolInfo = { 0 };
	symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
	symbolInfo.MaxNameLen = MAX_SYM_NAME;

	// Use SymFromName to look up symbols (including functions)
	if (SymFromName(ctx->sym_handle, symbol_name, &symbolInfo)) {
		return symbolInfo.Address - ctx->pdb_base_addr;
	}
	else {
		DWORD err = GetLastError();
		printf("[-] SymFromName failed for '%s': error %d (0x%x)\n", symbol_name, err, err);

		// Try as a type (for backward compatibility)
		SYMBOL_INFO_PACKAGE si = { 0 };
		si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
		si.si.MaxNameLen = sizeof(si.name);

		if (SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si)) {
			return si.si.Address - ctx->pdb_base_addr;
		}

		return 0;
	}
}
// -----------------------------------------------------------------
unsigned long long GetAndInsertSymbol(const char* str, symbol_ctx* symCtx, DWORD64 offset, BOOLEAN useOffset) {
	size_t strLen = strlen(str);
	if (strLen >= 32) {
		printf("[-] Maximum string size reached...\n");
		return 0x0;
	}
	if (SymbolsArrayIndex >= SymbolsArrayAllocationSize) {
		printf("[-] Maximum reached...\n");
		return 0x0;
	}
	// Cast to PBYTE so +sizeof(INIT) is exactly sizeof(INIT) bytes, not sizeof(INIT)² bytes.
	PSYMBOL CurrSymbolInArray = (PSYMBOL)((PBYTE)SymbolsArray + sizeof(INIT));

	if (!useOffset) {
		offset = GetSymbolOffset(symCtx, str);
	}
	memcpy(CurrSymbolInArray[SymbolsArrayIndex].name, std::move(str), strLen);
	CurrSymbolInArray[SymbolsArrayIndex].offset = offset;

	totalCopiedSize += strLen;
	SymbolsArrayIndex++;

	return offset;
}
// -----------------------------------------------------------------
BOOL AddInitData(unsigned long long NtBaseOffset, DWORD KPROCDirectoryTableBaseOffset, DWORD EPROCActiveProcessLinksOfsset, DWORD EPROCUniqueProcessIdOffset, const char* sourceProcess, const char* targetProcess) {
	PINIT Data = (PINIT)SymbolsArray;
	memcpy(Data[0].identifier, "INIT", 4);
	Data[0].NtBaseOffset = NtBaseOffset;
	printf("NTBaseOffset: 0x%llx\n", NtBaseOffset);
	if (sourceProcess != NULL) {
		size_t copyLenSource = min(strlen(sourceProcess), sizeof(Data[0].sourceProcess) - 1);
		memcpy(Data[0].sourceProcess, sourceProcess, copyLenSource);
	}
	if (targetProcess != NULL) {
		size_t copyLenTarget = min(strlen(targetProcess), sizeof(Data[0].targetProcess) - 1);
		memcpy(Data[0].targetProcess, targetProcess, copyLenTarget);
	}
	Data[0].KPROCDirectoryTableBaseOffset = KPROCDirectoryTableBaseOffset;
	Data[0].EPROCActiveProcessLinksOfsset = EPROCActiveProcessLinksOfsset;
	Data[0].EPROCUniqueProcessIdOffset = EPROCUniqueProcessIdOffset;
	return true;
}
// -----------------------------------------------------------------
DWORD64 GetKernelBase(_In_ std::string name) {
	/* Gets the base address (VIRTUAL ADDRESS) of a module in kernel address space */
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	// Grabs an array of all of the device drivers
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	// Makes sure that we successfully grabbed the drivers
	if (!success)
	{
		printf("[-] Unable to invoke EnumDeviceDrivers()!\n");
		return 0;
	}
	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++) {
		// Gets the name of the driver
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		// Compares the indexed driver and with our specified driver name
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			break;
		}
	}
	return imageBase;
}
// -----------------------------------------------------------------
void HexDump(void* pMemory, size_t size) {
	unsigned char* p = (unsigned char*)pMemory;

	for (size_t i = 0; i < size; i += 16) {  // Process 16 bytes per line
		printf("%08X  ", (unsigned int)i);   // Print offset

		// Print hex bytes
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size)
				printf("%02X ", p[i + j]);
			else
				printf("   ");  // Padding for alignment
		}

		printf(" | ");  // Separator

		// Print ASCII representation
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size) {
				unsigned char c = p[i + j];
				printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Printable ASCII or dot
			}
		}

		printf(" |\n");
	}
}
// -----------------------------------------------------------------
void CheckModifiedMemory(PVOID address, size_t size) {
	PVOID base = (PVOID)((unsigned long long)address & 0xfffffffffffff000);
	printf("[+] Checking memory at base: 0x%p\n", base);

	// Just read, don't modify permissions with VirtualProtect
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(base, &mbi, sizeof(mbi))) {
		printf("\t.. Memory protection: 0x%lx\n", mbi.Protect);
		printf("\t.. Memory state: %s\n",
			mbi.State == MEM_COMMIT ? "COMMIT" :
			mbi.State == MEM_RESERVE ? "RESERVE" : "FREE");
	}

	// Read directly from memory without changing permissions
	__try {
		printf("\t.. Memory content (first 16 bytes):\n");
		unsigned char* p = (unsigned char*)base;

		for (size_t i = 0; i < size; i += 16) {  // Process 16 bytes per line
			printf("\t\t%08X  ", (unsigned int)i);   // Print offset

			// Print hex bytes
			for (size_t j = 0; j < 16; j++) {
				if (i + j < size)
					printf("%02X ", p[i + j]);
				else
					printf("   ");  // Padding for alignment
			}

			printf(" | ");  // Separator

			// Print ASCII representation
			for (size_t j = 0; j < 16; j++) {
				if (i + j < size) {
					unsigned char c = p[i + j];
					printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Printable ASCII or dot
				}
			}

			printf(" |\n");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("[-] Exception when reading memory: 0x%lx\n", GetExceptionCode());
	}
}
// -----------------------------------------------------------------
const char* ProtectionToStr(PROTECTION prot) {
	switch (prot) {
	case _PAGE_NOACCESS:          return "PAGE_NOACCESS";
	case _PAGE_READONLY:          return "PAGE_READONLY";
	case _PAGE_EXECUTE:           return "PAGE_EXECUTE";
	case _PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ";
	case _PAGE_READWRITE:         return "PAGE_READWRITE";
	case _PAGE_WRITECOPY:         return "PAGE_WRITECOPY";
	case _PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
	case _PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
	default:                      return "UNKNOWN_PROTECTION";
	}
}
// -----------------------------------------------------------------

// Build a raw _MMVAD_FLAGS DWORD from PDB-derived bit positions.
// protection : 5-bit MM_PROTECT value (01=RO, 04=RW, 07=RWX, etc.)
// vadType    : 3-bit MI_VAD_TYPE
// isPrivate  : 1 for private memory, 0 for section/image
ULONG BuildVadFlagsRaw(ULONG protection, ULONG vadType, ULONG isPrivate) {
	ULONG raw = 0;
	if (g_MmVadFlags.valid) {
		const BITFIELD_MEMBER* mProt    = FindBitfieldMember(g_MmVadFlags.members, g_MmVadFlags.count, "Protection");
		const BITFIELD_MEMBER* mVadType = FindBitfieldMember(g_MmVadFlags.members, g_MmVadFlags.count, "VadType");
		const BITFIELD_MEMBER* mPriv    = FindBitfieldMember(g_MmVadFlags.members, g_MmVadFlags.count, "PrivateMemory");
		if (mProt)    raw |= (protection & ((1u << mProt->bitLen)    - 1u)) << mProt->bitPos;
		if (mVadType) raw |= (vadType    & ((1u << mVadType->bitLen) - 1u)) << mVadType->bitPos;
		if (mPriv)    raw |= (isPrivate  & 1u)                              << mPriv->bitPos;
	} else {
		// PDB not loaded — fall back to known Windows 10/11 positions
		// Protection at bit 7 (5 bits), VadType at bit 4 (3 bits), PrivateMemory at bit 20
		raw |= (protection & 0x1F) << 7;
		raw |= (vadType    & 0x07) << 4;
		raw |= (isPrivate  & 0x01) << 20;
	}
	return raw;
}

// Build a short type-tag string from VadFlagsRaw + ControlAreaFlags using PDB layouts.
// Tag priority: Private > Image > File > Pagefile > Physical > Global > Shared
void BuildVadTypeTag(ULONG vf, ULONG ca, BOOLEAN isShort, ULONG mappedViews, ULONG sectionRefs, char* out, size_t outLen) {
	// _MMVAD_FLAGS is the single primary layout for both _MMVAD_SHORT and _MMVAD
	const BITFIELD_LAYOUT* flagLayout = g_MmVadFlags.valid ? &g_MmVadFlags : NULL;
	if (!flagLayout) { strcpy_s(out, outLen, ""); return; }

	ULONG vadType    = GetFlag(flagLayout, vf, "VadType");
	ULONG isPrivate  = GetFlag(flagLayout, vf, "PrivateMemory");
	ULONG isImage    = GetFlag(&g_MmSectionFlags, ca, "Image");
	ULONG isFile     = GetFlag(&g_MmSectionFlags, ca, "File");
	ULONG isPhys     = GetFlag(&g_MmSectionFlags, ca, "PhysicalMemory");
	ULONG isGlobal   = GetFlag(&g_MmSectionFlags, ca, "GlobalMemory");
	ULONG isNullFP   = GetFlag(&g_MmSectionFlags, ca, "FilePointerNull");

	// Human-readable names matching the MI_VAD_TYPE enum values 0-7.
	static const char* vadTypeNames[] = {
		"Private", "DevPhys", "Image", "AWE", "WrtWatch", "LrgPage", "RotPhys", "LrgPgSec"
	};

	char buf[48] = "";

	// VadType (3 bits in MMVAD_FLAGS) is the authoritative classification set by
	// the kernel when the VAD was originally created.  We inserted our nodes with
	// the caller-chosen VadType, so trust it first.  CA->LongFlags.Image is a
	// driver-internal flag we set only to survive MiDeleteVad — it must NOT
	// override the real VadType for display purposes.
	if (isPrivate) {
		// Private nodes: VadType distinguishes sub-variants.
		if (vadType < 8)
			strcpy_s(buf, sizeof(buf), vadTypeNames[vadType]);
		else
			snprintf(buf, sizeof(buf), "Prv[%u]", vadType);
	} else {
		// Non-private: VadType takes precedence over CA bits.
		if (vadType > 0 && vadType < 8) {
			strcpy_s(buf, sizeof(buf), vadTypeNames[vadType]);
		} else if (ca != 0) {
			// VadType==0, non-private, with a ControlArea.
			// Do NOT use isImage here: we set CA->LongFlags.Image on all phantom
			// non-private nodes to prevent MiRemoveSharedCommitNode from crashing
			// on process exit.  A real kernel Image node always has VadType==2;
			// VadType==0 with Image set only means our survival workaround.
			if (isPhys)                         strcpy_s(buf, sizeof(buf), "Physical");
			else if (isFile && !isNullFP)       strcpy_s(buf, sizeof(buf), "File");
			else if (isGlobal && isNullFP)      strcpy_s(buf, sizeof(buf), "Global/Shared");
			else if (isGlobal)                  strcpy_s(buf, sizeof(buf), "Global");
			else if (isNullFP)                  strcpy_s(buf, sizeof(buf), "Pagefile");
			else                                strcpy_s(buf, sizeof(buf), "Section");
		} else if (!isShort) {
			// VadType==0, non-private, no CA flags — has a Subsection chain but
			// CA->LongFlags is all zero (our synthetic Section nodes before driver fix,
			// or any future node type we create without specific CA flags).
			strcpy_s(buf, sizeof(buf), "Section");
		} else {
			// _MMVAD_SHORT with no Subsection — pure MEM_RESERVE (no commit charges).
			strcpy_s(buf, sizeof(buf), "Reserve");
		}
	}

	if (mappedViews > 0) {
		char suffix[16];
		snprintf(suffix, sizeof(suffix), " [%uv]", mappedViews);
		strncat_s(buf, sizeof(buf), suffix, _TRUNCATE);
	}
	strcpy_s(out, outLen, buf);
}
// -----------------------------------------------------------------
void GetSymOffsets(PVOID SecBase, size_t SecSize,
	PVOID FileNameSecBase,
	SIZE_T FileNameSecSize) {
	if (SecBase == NULL)
		return;

	PVAD_NODE      node         = (PVAD_NODE)SecBase;
	PVAD_NODE_FILE FileNameBase = (PVAD_NODE_FILE)FileNameSecBase;
	size_t maxSymCount  = SecSize / sizeof(VAD_NODE);
	size_t maxFileNames = FileNameSecSize / sizeof(VAD_NODE_FILE);

	printf("\n%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"Lvl", "VADNode", "StartingVpn", "EndingVpn", "4KBs",
		"Protection", "Type", "FileName");
	printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"-----", "-----------------", "-------------", "-------------", "---------",
		"--------------------------", "--------------", "-----------------------------------");

	__try {
		for (size_t i = 0; i < maxSymCount - 1; i++) {
			if (node[i].Level == 0) continue;

			if (node[i].Level == -1 && node[i].StartingVpn == 0xFFFFFFFFFFFFFFFEULL) {
				printf("\n  ---- [ Source Process ] -------------------------------------------------------------------------\n");
				printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"Lvl", "VADNode", "StartingVpn", "EndingVpn", "4KBs",
					"Protection", "Type", "FileName");
				printf("%-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"-----", "-----------------", "-------------", "-------------", "---------",
					"--------------------------", "--------------", "-----------------------------------");
				continue;
			}

			PROTECTION prot = (PROTECTION)node[i].Protection;
			const char* fileName = (node[i].FileOffset && node[i].FileOffset < maxFileNames)
				? (FileNameBase[node[i].FileOffset].DevPath[0]
				   ? FileNameBase[node[i].FileOffset].DevPath
				   : FileNameBase[node[i].FileOffset].FileName)
				: "-";

			char typeTag[48] = "";
			if (g_MmSectionFlags.valid)
				BuildVadTypeTag(node[i].VadFlagsRaw, node[i].ControlAreaFlags, node[i].IsVadShort,
					node[i].MappedViews, node[i].SectionReferences, typeTag, sizeof(typeTag));

			char protBuf[40];
			snprintf(protBuf, sizeof(protBuf), "%-22s [0x%x]",
				ProtectionToStr(prot), node[i].Protection);

			printf("%-5d  0x%-16p  0x%011I64x  0x%011I64x  %-9I64u  %-26s  %-14s  %-35s\n",
				node[i].Level,
				node[i].VADNode,
				node[i].StartingVpn,
				node[i].EndingVpn,
				node[i].EndingVpn - node[i].StartingVpn + 1,
				protBuf,
				typeTag,
				fileName);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Exception when reading VAD data: 0x%lx\n", GetExceptionCode());
	}
}
// -----------------------------------------------------------------
void UpdateInitData(PVOID symbolsArray,
	const char* sourceProcess,
	const char* targetProcess,
	unsigned long long sourceVA,
	unsigned long long targetVPN,
	ULONG newProtection) {
	PINIT Data = (PINIT)symbolsArray;
	if (sourceProcess != NULL) {
		size_t copyLenSource = min(strlen(sourceProcess), sizeof(Data[0].sourceProcess) - 1);
		memset(Data[0].sourceProcess, 0, sizeof(Data[0].sourceProcess));
		memcpy(Data[0].sourceProcess, sourceProcess, copyLenSource);
	}
	if (targetProcess != NULL) {
		size_t copyLenTarget = min(strlen(targetProcess), sizeof(Data[0].targetProcess) - 1);
		memset(Data[0].targetProcess, 0, sizeof(Data[0].targetProcess));
		memcpy(Data[0].targetProcess, targetProcess, copyLenTarget);
	}
	if (sourceVA != 0x0)
		Data[0].sourceVA = sourceVA;
	if (targetVPN != 0x0)
		Data[0].targetVPN = targetVPN;
	if (newProtection != 0)
		Data[0].requestedProtection = newProtection;

}
void AddInitDataSection(symbol_ctx* sym_ctxNtskrnl) {
	if (sym_ctxNtskrnl == NULL) {
		printf("Symbols for ntoskrnl.exe not available, download failed, aborting...\n");
		exit(1);
	}
	unsigned long long ntBase = GetKernelBase("ntoskrnl.exe"); // DWORD64
	unsigned long long eprocUniqueProcessId = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"UniqueProcessId");
	unsigned long long eprocActiveProcessLinks = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"ActiveProcessLinks");
	unsigned long long kprocDirectoryTableBase = GetFieldOffset(sym_ctxNtskrnl, "_KPROCESS", L"DirectoryTableBase");// Parse command line arguments]

	if (AddInitData(ntBase, kprocDirectoryTableBase, eprocActiveProcessLinks, eprocUniqueProcessId, 0x0, 0x0))
		printf("[*] InitData added successfully\n");

	GetAndInsertSymbol("ZwProtectVirtualMemory", sym_ctxNtskrnl, 0x0, false);
	GetAndInsertSymbol("eprocUniqueProcessId", sym_ctxNtskrnl, eprocUniqueProcessId, true); // TODO: exceution stops here???
	GetAndInsertSymbol("eprocActiveProcessLinks", sym_ctxNtskrnl, eprocActiveProcessLinks, true);
	GetAndInsertSymbol("kprocDirectoryTableBase", sym_ctxNtskrnl, kprocDirectoryTableBase, true);
	unsigned long long VADRoot = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"VadRoot");
	unsigned long long StartingVpn1 = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"StartingVpn");
	unsigned long long EndingVpn1 = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"EndingVpn");
	unsigned long long Left = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"Left");
	unsigned long long Right = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"Right");
	GetAndInsertSymbol("VADRoot", sym_ctxNtskrnl, VADRoot, true);
	GetAndInsertSymbol("StartingVpn", sym_ctxNtskrnl, StartingVpn1, true);
	GetAndInsertSymbol("EndingVpn", sym_ctxNtskrnl, EndingVpn1, true);
	GetAndInsertSymbol("Left", sym_ctxNtskrnl, Left, true);
	GetAndInsertSymbol("Right", sym_ctxNtskrnl, Right, true);
	unsigned long long MMVADSubsection = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD", L"Subsection");
	unsigned long long MMVADControlArea = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD", L"ControlArea"); // actually at Off: 0x0 and its _CONTROL_AREA*
	unsigned long long MMVADCAFilePointer = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"FilePointer");
	unsigned long long MMCAFlags         = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"u");
	unsigned long long MMCAMappedViews   = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"NumberOfMappedViews");
	unsigned long long MMCASectionRefs   = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"NumberOfSectionReferences");
	GetAndInsertSymbol("MMVADSubsection",        sym_ctxNtskrnl, MMVADSubsection,    true);
	GetAndInsertSymbol("MMVADControlArea",       sym_ctxNtskrnl, MMVADControlArea,   true);
	GetAndInsertSymbol("MMVADCAFilePointer",     sym_ctxNtskrnl, MMVADCAFilePointer, true);
	GetAndInsertSymbol("MMCAFlags",              sym_ctxNtskrnl, MMCAFlags,          true);
	GetAndInsertSymbol("MMCAMappedViews",        sym_ctxNtskrnl, MMCAMappedViews,    true);
	GetAndInsertSymbol("MMCASectionReferences",  sym_ctxNtskrnl, MMCASectionRefs,    true);
	unsigned long long FILEOBJECTFileName = GetFieldOffset(sym_ctxNtskrnl, "_FILE_OBJECT", L"FileName");
	GetAndInsertSymbol("FILEOBJECTFileName", sym_ctxNtskrnl, FILEOBJECTFileName, true);
	unsigned long long EPROCImageFileName = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"ImageFileName");
	GetAndInsertSymbol("EPROCImageFileName", sym_ctxNtskrnl, EPROCImageFileName, true);
	unsigned long long EPROCProtection = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"Protection");
	GetAndInsertSymbol("EPROCProtection", sym_ctxNtskrnl, EPROCProtection, true);
	// _OBJECT_HEADER layout — needed to walk back from object body to name info
	{
		unsigned long long objHdrBody      = GetFieldOffset(sym_ctxNtskrnl, "_OBJECT_HEADER", L"Body");
		unsigned long long objHdrInfoMask  = GetFieldOffset(sym_ctxNtskrnl, "_OBJECT_HEADER", L"InfoMask");
		unsigned long long objHdrNameInfoSz = GetTypeSize(sym_ctxNtskrnl,  "_OBJECT_HEADER_NAME_INFO");
		unsigned long long sectionSegment  = GetFieldOffset(sym_ctxNtskrnl, "_SECTION",        L"u1");
		unsigned long long caSegment       = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA",   L"Segment");
		GetAndInsertSymbol("ObjHdrSize",         sym_ctxNtskrnl, objHdrBody,         true);
		GetAndInsertSymbol("ObjHdrInfoMaskOff",  sym_ctxNtskrnl, objHdrInfoMask,     true);
		GetAndInsertSymbol("ObjHdrNameInfoSz",   sym_ctxNtskrnl, objHdrNameInfoSz,   true);
		GetAndInsertSymbol("SectionSegmentOff",  sym_ctxNtskrnl, sectionSegment,     true);
		GetAndInsertSymbol("CASegmentOff",       sym_ctxNtskrnl, caSegment,          true);
	}
	unsigned long long PEB = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"Peb");
	unsigned long long PEBLdr = GetFieldOffset(sym_ctxNtskrnl, "_PEB", L"Ldr");
	unsigned long long LdrListHead = GetFieldOffset(sym_ctxNtskrnl, "_PEB_LDR_DATA", L"InMemoryOrderModuleList");
	unsigned long long LdrListEntry = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"InMemoryOrderLinks");
	unsigned long long LdrBaseDllName = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"BaseDllName");
	unsigned long long LdrBaseDllBase = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"DllBase");
	GetAndInsertSymbol("PEB", sym_ctxNtskrnl, PEB, true);
	GetAndInsertSymbol("PEBLdr", sym_ctxNtskrnl, PEBLdr, true);
	GetAndInsertSymbol("LdrListHead", sym_ctxNtskrnl, LdrListHead, true);
	GetAndInsertSymbol("LdrListEntry", sym_ctxNtskrnl, LdrListEntry, true);
	GetAndInsertSymbol("LdrBaseDllName", sym_ctxNtskrnl, LdrBaseDllName, true);
	GetAndInsertSymbol("LdrBaseDllBase", sym_ctxNtskrnl, LdrBaseDllBase, true);

	// AVL tree modification fields
	unsigned long long ParentValue        = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"ParentValue");
	unsigned long long AddressCreationLock = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS",          L"AddressCreationLock");
	unsigned long long VadHint            = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS",          L"VadHint");
	unsigned long long VadFreeHint        = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS",          L"VadFreeHint");
	GetAndInsertSymbol("ParentValue",         sym_ctxNtskrnl, ParentValue,         true);
	GetAndInsertSymbol("AddressCreationLock", sym_ctxNtskrnl, AddressCreationLock, true);
	GetAndInsertSymbol("VadHint",             sym_ctxNtskrnl, VadHint,             true);
	GetAndInsertSymbol("VadFreeHint",         sym_ctxNtskrnl, VadFreeHint,         true);

	// Kernel MM internal helpers — absolute addresses (ntBase + PDB RVA)
	unsigned long long MiCheckForConflictingVad    = GetSymbolOffset(sym_ctxNtskrnl, "MiCheckForConflictingVad");
	unsigned long long MiInsertVad                 = GetSymbolOffset(sym_ctxNtskrnl, "MiInsertVad");
	unsigned long long MiInsertVadCharges          = GetSymbolOffset(sym_ctxNtskrnl, "MiInsertVadCharges");
	unsigned long long MiRemoveVad                 = GetSymbolOffset(sym_ctxNtskrnl, "MiRemoveVad");
	unsigned long long MiRemoveVadCharges          = GetSymbolOffset(sym_ctxNtskrnl, "MiRemoveVadCharges");
	unsigned long long MiInitializePrototypePtes   = GetSymbolOffset(sym_ctxNtskrnl, "MiInitializePrototypePtes");
	unsigned long long MiMakeDemandZeroPte         = GetSymbolOffset(sym_ctxNtskrnl, "MiMakeDemandZeroPte");
	unsigned long long MiUpdateControlAreaCommitCount = GetSymbolOffset(sym_ctxNtskrnl, "MiUpdateControlAreaCommitCount");
	if (!MiInsertVad)
		printf("[!] MiInsertVad not found in PDB — Mi* path will be skipped, manual AVL fallback active\n");
	if (!MiInitializePrototypePtes)
		printf("[!] MiInitializePrototypePtes not found in PDB — non-private VAD nodes will use zero PTEs (not committed)\n");
	if (!MiUpdateControlAreaCommitCount)
		printf("[!] MiUpdateControlAreaCommitCount not found in PDB — CommitCharge will stay 0, memory may not be MEM_COMMIT\n");
	GetAndInsertSymbol("MiCheckForConflictingVad",      sym_ctxNtskrnl, MiCheckForConflictingVad,         false);
	GetAndInsertSymbol("MiInsertVad",                   sym_ctxNtskrnl, MiInsertVad,                      false);
	GetAndInsertSymbol("MiInsertVadCharges",            sym_ctxNtskrnl, MiInsertVadCharges,               false);
	GetAndInsertSymbol("MiRemoveVad",                   sym_ctxNtskrnl, MiRemoveVad,                      false);
	GetAndInsertSymbol("MiRemoveVadCharges",            sym_ctxNtskrnl, MiRemoveVadCharges,               false);
	GetAndInsertSymbol("MiInitializePrototypePtes",     sym_ctxNtskrnl, MiInitializePrototypePtes,        false);
	GetAndInsertSymbol("MiMakeDemandZeroPte",           sym_ctxNtskrnl, MiMakeDemandZeroPte,              false);
	GetAndInsertSymbol("MiUpdateControlAreaCommitCount",sym_ctxNtskrnl, MiUpdateControlAreaCommitCount,   false);

	// ---- PDB-derived bitfield layouts ----------------------------------------
	// Populate global decode tables for all MMVAD_FLAGS variants + _MMSECTION_FLAGS.
	// These are used by ShowTree (usermode) and their bit-positions are also sent
	// to the kernel via SYM_INFO so WalkVADIterative never uses hardcoded offsets.
	g_MmVadFlags.count      = GetBitfieldMembers(sym_ctxNtskrnl, "_MMVAD_FLAGS",  g_MmVadFlags.members,  MAX_BITFIELD_MEMBERS);
	g_MmVadFlags.valid      = g_MmVadFlags.count > 0;
	g_MmVadFlags1.count     = GetBitfieldMembers(sym_ctxNtskrnl, "_MMVAD_FLAGS1", g_MmVadFlags1.members, MAX_BITFIELD_MEMBERS);
	g_MmVadFlags1.valid     = g_MmVadFlags1.count > 0;
	g_MmVadFlags2.count     = GetBitfieldMembers(sym_ctxNtskrnl, "_MMVAD_FLAGS2", g_MmVadFlags2.members, MAX_BITFIELD_MEMBERS);
	g_MmVadFlags2.valid     = g_MmVadFlags2.count > 0;
	g_MmSectionFlags.count  = GetBitfieldMembers(sym_ctxNtskrnl, "_MMSECTION_FLAGS", g_MmSectionFlags.members, MAX_BITFIELD_MEMBERS);
	g_MmSectionFlags.valid  = g_MmSectionFlags.count > 0;

	/*printf("[*] Bitfield layouts: _MMVAD_FLAGS=%u _MMVAD_FLAGS1=%u _MMVAD_FLAGS2=%u _MMSECTION_FLAGS=%u members\n",
		g_MmVadFlags.count, g_MmVadFlags1.count, g_MmVadFlags2.count, g_MmSectionFlags.count);
	if (g_MmVadFlags.count > 0) {
		printf("[*] _MMVAD_FLAGS members:\n");
		for (DWORD i = 0; i < g_MmVadFlags.count; i++)
			printf("    [%2u] %-24s  bitPos=%2u  bitLen=%u\n", i,
				g_MmVadFlags.members[i].name,
				g_MmVadFlags.members[i].bitPos,
				g_MmVadFlags.members[i].bitLen);
	}
	if (g_MmSectionFlags.count > 0) {
		printf("[*] _MMSECTION_FLAGS members:\n");
		for (DWORD i = 0; i < g_MmSectionFlags.count; i++)
			printf("    [%2u] %-24s  bitPos=%2u  bitLen=%u\n", i,
				g_MmSectionFlags.members[i].name,
				g_MmSectionFlags.members[i].bitPos,
				g_MmSectionFlags.members[i].bitLen);
	}*/

	// _MMVAD primary flags — _MMVAD_FLAGS contains VadType, Protection, PrivateMemory
	// at the same bit positions for both _MMVAD_SHORT.Core.u and full _MMVAD.Core.u
	unsigned long long MMVADFlagsOffset = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"u");
	GetAndInsertSymbol("MMVADFlagsOffset", sym_ctxNtskrnl, MMVADFlagsOffset, true);

	const BITFIELD_LAYOUT* flPrimary = g_MmVadFlags.valid ? &g_MmVadFlags : NULL;
	const BITFIELD_MEMBER* mProt    = flPrimary ? FindBitfieldMember(flPrimary->members, flPrimary->count, "Protection")    : NULL;
	const BITFIELD_MEMBER* mVadType = flPrimary ? FindBitfieldMember(flPrimary->members, flPrimary->count, "VadType")        : NULL;
	const BITFIELD_MEMBER* mPriv    = flPrimary ? FindBitfieldMember(flPrimary->members, flPrimary->count, "PrivateMemory")  : NULL;
	GetAndInsertSymbol("ProtectionBitPos",    sym_ctxNtskrnl, mProt    ? mProt->bitPos    : 7,  true);
	GetAndInsertSymbol("ProtectionBitLen",    sym_ctxNtskrnl, mProt    ? mProt->bitLen    : 5,  true);
	GetAndInsertSymbol("VadTypeBitPos",       sym_ctxNtskrnl, mVadType ? mVadType->bitPos : 4,  true);
	GetAndInsertSymbol("VadTypeBitLen",       sym_ctxNtskrnl, mVadType ? mVadType->bitLen : 3,  true);
	GetAndInsertSymbol("PrivateMemoryBitPos", sym_ctxNtskrnl, mPriv    ? mPriv->bitPos    : 20, true);
}

// -----------------------------------------------------------------
// Converts a hex string (like "41 42 ?? 44") to byte array and mask
// Returns true if conversion successful, false otherwise
bool ParseHexPattern(const char* hexPattern, std::vector<unsigned char>& pattern, std::vector<bool>& mask) {
	pattern.clear();
	mask.clear();

	if (!hexPattern || *hexPattern == '\0')
		return false;

	const char* ptr = hexPattern;
	while (*ptr) {
		// Skip whitespace
		if (isspace(*ptr)) {
			ptr++;
			continue;
		}

		// Handle wildcards
		if (*ptr == '?') {
			pattern.push_back(0);
			mask.push_back(false);  // false = ignore this byte when matching
			ptr++;
			// Skip second question mark if present (for "??" notation)
			if (*ptr == '?')
				ptr++;
		}
		// Process hex byte
		else if (isxdigit(ptr[0]) && isxdigit(ptr[1])) {
			char byteStr[3] = { ptr[0], ptr[1], 0 };
			unsigned char byte = (unsigned char)strtoul(byteStr, nullptr, 16);
			pattern.push_back(byte);
			mask.push_back(true);  // true = check this byte when matching
			ptr += 2;
		}
		else {
			// Invalid character
			return false;
		}
	}

	return !pattern.empty();
}

// -----------------------------------------------------------------
// Searches for pattern in a range of memory
// Returns vector of offsets where pattern was found
std::vector<size_t> ScanMemory(const void* memoryStart, size_t memorySize, const char* hexPattern) {
	std::vector<size_t> results;

	if (!memoryStart || !hexPattern || memorySize == 0)
		return results;

	// Convert hex pattern to bytes and mask
	std::vector<unsigned char> pattern;
	std::vector<bool> mask;

	if (!ParseHexPattern(hexPattern, pattern, mask))
		return results;

	if (pattern.size() > memorySize)
		return results;  // Pattern is larger than scan range

	const unsigned char* memory = static_cast<const unsigned char*>(memoryStart);

	// Scan through memory
	for (size_t i = 0; i <= memorySize - pattern.size(); i++) {
		bool found = true;

		for (size_t j = 0; j < pattern.size(); j++) {
			// If mask[j] is true, check byte; otherwise, it's a wildcard
			if (mask[j] && memory[i + j] != pattern[j]) {
				found = false;
				break;
			}
		}

		if (found) {
			results.push_back(i);
		}
	}

	return results;
}

#define min(a,b)            (((a) < (b)) ? (a) : (b))
// -----------------------------------------------------------------
// Helper function that scans memory and prints results
bool ScanAndPrintMemory(const void* address, const char* hexPattern) {
	//printf("[*] Scanning 4096 bytes at address 0x%p for pattern: %s\n", address, hexPattern);

	// Use Structured Exception Handling to prevent crashes on invalid memory
	//__try {
		// First, convert the pattern to get its size
		std::vector<unsigned char> pattern;
		std::vector<bool> mask;
		if (!ParseHexPattern(hexPattern, pattern, mask)) {
			printf("[-] Invalid hex pattern format\n");
			return 0;
		}

		// Now perform the scan
		std::vector<size_t> matches = ScanMemory(address, 4096, hexPattern);

		if (matches.empty()) {
			printf("[-] No matches found\n");
			return 0;
		}

		if (matches.size() >= 1) {
			printf("[+] Found %zu matches:\n", matches.size());
			// Print each match with surrounding context
			const unsigned char* memory = static_cast<const unsigned char*>(address);
			for (size_t offset : matches) {
				printf("[+] Match at offset 0x%04zx (address 0x%p):\n", offset, static_cast<const unsigned char*>(address) + offset);

				// Display hex dump of found pattern with context
				printf("    ");

				// Determine context range (8 bytes before, 8 bytes after)
				size_t contextStart = offset > 8 ? offset - 8 : 0;
				size_t contextEnd = min(offset + pattern.size() + 8, 4096ULL);

				// Print hex bytes
				for (size_t i = contextStart; i < contextEnd; i++) {
					if (i == offset) printf("[ ");
					printf("%02X ", memory[i]);
					if (i == offset + pattern.size() - 1) printf("] ");
				}

				printf("\n    ");

				// Print ASCII representation
				for (size_t i = contextStart; i < contextEnd; i++) {
					if (i == offset) printf("|");
					char c = memory[i];
					printf("%c", (c >= 32 && c <= 126) ? c : '.');
					if (i == offset + pattern.size() - 1) printf("|");
				}

				printf("\n");
			}
			return 1;
		}
	//}
	//__except (EXCEPTION_EXECUTE_HANDLER) {
	//	printf("[-] Exception occurred while accessing memory: 0x%lx\n");
	//}
}

// -----------------------------------------------------------------
// Prints the VAD tree as a numbered, indented list.
// -----------------------------------------------------------------
size_t ShowTree(PVOID SecBase, size_t SecSize,
	PVOID FileNameSecBase, size_t FileNameSecSize,
	unsigned long long* selectedVpns, size_t maxVpns) {
	if (!SecBase) return 0;

	PVAD_NODE      node     = (PVAD_NODE)SecBase;
	PVAD_NODE_FILE fileBase = (PVAD_NODE_FILE)FileNameSecBase;
	size_t maxNodes   = SecSize / sizeof(VAD_NODE);
	size_t maxNames   = FileNameSecSize / sizeof(VAD_NODE_FILE);
	size_t count      = 0;

	printf("\n%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"#", "Lvl", "VADNode", "StartVpn", "EndVpn", "4KBs",
		"Protection", "Type", "FileName");
	printf("%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
		"---", "-----", "-----------------", "-------------", "-------------", "---------",
		"--------------------------", "--------------", "-----------------------------------");

	__try {
		for (size_t i = 0; i < maxNodes - 1; i++) {
			if (node[i].Level == 0) continue;

			// Sentinel written by kernel for mode=2 (both) to separate sections
			if (node[i].Level == -1 && node[i].StartingVpn == 0xFFFFFFFFFFFFFFFEULL) {
				printf("\n  ---- [ Source Process ] -------------------------------------------------------------------------\n");
				printf("%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"#", "Lvl", "VADNode", "StartVpn", "EndVpn", "4KBs",
					"Protection", "Type", "FileName");
				printf("%-4s  %-5s  %-18s  %-13s  %-13s  %-9s  %-26s  %-14s  %-35s\n",
					"---", "-----", "-----------------", "-------------", "-------------", "---------",
					"--------------------------", "--------------", "-----------------------------------");
				continue;
			}

			unsigned long long vpn  = node[i].StartingVpn;
			PROTECTION prot         = (PROTECTION)node[i].Protection;
			const char* fileName    = (node[i].FileOffset && node[i].FileOffset < maxNames)
									 ? (fileBase[node[i].FileOffset].DevPath[0]
										? fileBase[node[i].FileOffset].DevPath
										: fileBase[node[i].FileOffset].FileName)
									 : "-";

			// Decode type tag from PDB-derived layout maps
			char typeTag[48] = "";
			if (g_MmSectionFlags.valid)
				BuildVadTypeTag(node[i].VadFlagsRaw, node[i].ControlAreaFlags, node[i].IsVadShort,
					node[i].MappedViews, node[i].SectionReferences, typeTag, sizeof(typeTag));

			// Protection string with raw value appended
			char protBuf[40];
			snprintf(protBuf, sizeof(protBuf), "%-22s [0x%x]",
				ProtectionToStr(prot), node[i].Protection);

			// indent by level with a leading symbol
			char indent[32] = { 0 };
			int d = (node[i].Level - 1) < 10 ? (node[i].Level - 1) : 10;
			for (int j = 0; j < d; j++) indent[j] = ' ';
			indent[d] = (node[i].Level == 1) ? '*' : (d % 2 == 0 ? '+' : '-');

			printf("%-4zu  %s%-*d  0x%-16p  0x%011llx  0x%011llx  %-9llu  %-26s  %-14s  %-35s\n",
				count,
				indent, (int)(6 - (int)strlen(indent)), node[i].Level,
				node[i].VADNode,
				vpn, node[i].EndingVpn,
				node[i].EndingVpn - vpn + 1,
				protBuf,
				typeTag,
				fileName);

			if (selectedVpns && count < maxVpns)
				selectedVpns[count] = vpn;
			count++;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		printf("[!] Exception reading VAD data\n");
	}
	printf("\n[%zu nodes]\n", count);
	return count;
}

void ShowHelp() {
	BoxTop("Process");
	BoxRow("  I  set source process    O  set target process");
	BoxMid("VAD Tree");
	BoxRow("  1  populate    2  quick view    T  indexed view");
	BoxRow("  N  insert node  D  delete node  V  map-view  F  find viewers");
	BoxRow("  4  link PTE     X  unlink");
	BoxMid("Memory");
	BoxRow("  Q  read virt    E  write virt   M  set view size");
	BoxRow("  R  read phys    W  write phys");
	BoxRow("  P  pattern scan              A  change protection");
	BoxMid("Dump");
	BoxRow("  Z  [D=minidump  P=strip protection+handle]");
	BoxMid("Exit");
	BoxRow("  5  exit+cleanup             6  silent exit");
	BoxBot();
}

// =================================================================
// main
// =================================================================
int main(int argc, char* argv[]) {
    TCHAR ntPath[MAX_PATH] = {};
    _tcscat_s(ntPath, _countof(ntPath), TEXT("C:\\Windows\\System32\\ntoskrnl.exe"));
    symbol_ctx* sym_ctxNtskrnl = LoadSymbolsFromImageFile(ntPath);

	HANDLE hMapFile = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_TO);
	if (!hMapFile) { printf("[-] Symbol mapping open failed: %lu\n", GetLastError()); return 1; }
	SymbolsArray = MapViewOfFile(hMapFile, FILE_MAP_WRITE, 0, 0, 4096 * 2);
	if (!SymbolsArray) { printf("[-] Symbol map view failed: %lu\n", GetLastError()); return 1; }
	// Capacity derived from the mapped view size — no hardcoded count needed.
	// Adding new GetAndInsertSymbol calls never requires a manual bump here.
	SymbolsArrayAllocationSize = (4096 * 2 - sizeof(INIT)) / sizeof(SYMBOL);
	totalAllocationSize += SymbolsArrayAllocationSize;

    // Parse command-line
    char initSourceBuf[32] = {}, initTargetBuf[32] = {};
    const char* initSource = NULL, *initTarget = NULL;
    unsigned long long initVPN = 0, initVPNOff = 0;
    size_t initVPNSize = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "/t") && i+1 < argc) {
            strncpy_s(initTargetBuf, argv[++i], _TRUNCATE);
            initTarget = initTargetBuf;

        }
        if (!strcmp(argv[i], "/s") && i+1 < argc) {
            strncpy_s(initSourceBuf, argv[++i], _TRUNCATE);
            initSource = initSourceBuf;

        }
        if (!strcmp(argv[i], "/i") && i+1 < argc) {
            const char* v = argv[++i];
            initVPN = strtoull((strncmp(v, "0x", 2) == 0) ? v+2 : v, NULL, 16);
            printf("[*] VPN: 0x%llx\n", initVPN);
        }
        if (!strcmp(argv[i], "/m") && i+1 < argc) { initVPNSize = (size_t)atoi(argv[++i]); }
        if (!strcmp(argv[i], "/o") && i+1 < argc) {
            const char* v = argv[++i];
            initVPNOff = strtoull((strncmp(v, "0x", 2) == 0) ? v+2 : v, NULL, 16);
        }
    }
    if (initVPN) initVPN += initVPNOff;

    // Open shared sections
    HANDLE hVADMapFile = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_FROM);
    if (!hVADMapFile) { printf("[-] VAD mapping: %lu\n", GetLastError()); return 1; }
    PVOID VADArray = MapViewOfFile(hVADMapFile, FILE_MAP_WRITE, 0, 0, 0);
    if (!VADArray) { printf("[-] VAD map view: %lu\n", GetLastError()); return 1; }

    HANDLE hVADMapFN = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_FROM_FILENAMES);
    if (!hVADMapFN) { printf("[-] VAD FN mapping: %lu\n", GetLastError()); return 1; }
    PVOID VADArrayFileName = MapViewOfFile(hVADMapFN, FILE_MAP_WRITE, 0, 0, 0);
    if (!VADArrayFileName) { printf("[-] VAD FN map view: %lu\n", GetLastError()); return 1; }

    HANDLE hEventUSERMODEREADY = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_USERMODEREADY_EVENT);
    HANDLE hEventLINK          = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_LINK_EVENT);
    HANDLE hEventUnlink        = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_Unlink_EVENT);
    HANDLE hEventINIT          = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_INIT_EVENT);
    if (!hEventUSERMODEREADY || !hEventLINK || !hEventUnlink || !hEventINIT) {
        printf("[-] Core events open failed: %lu\n", GetLastError()); return 1;
    }

    HANDLE hEventWRITE_PHYS  = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_WRITE_PHYS_EVENT);
    HANDLE hWritePhysMapFile  = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_WRITE_PHYS);
    PVOID  WritePhysArray     = hWritePhysMapFile ? MapViewOfFile(hWritePhysMapFile, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    if (!hEventWRITE_PHYS || !WritePhysArray) {
        printf("[-] WritePhys setup failed: %lu\n", GetLastError()); return 1;
    }

    HANDLE hEventREAD_PHYS   = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_READ_PHYS_EVENT);
    HANDLE hReadPhysMapFile   = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_READ_PHYS);
    PVOID  ReadPhysArray      = hReadPhysMapFile ? MapViewOfFile(hReadPhysMapFile, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    if (!hEventREAD_PHYS || !ReadPhysArray) {
        printf("[-] ReadPhys setup failed: %lu\n", GetLastError()); return 1;
    }

    HANDLE hVadModifyMapFile  = OpenFileMappingW(SECTION_MAP_WRITE, FALSE, MAPPING_NAME_VAD_MODIFY);
    PVOID  VadModifyArray     = hVadModifyMapFile ? MapViewOfFile(hVadModifyMapFile, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    HANDLE hEventVAD_INSERT   = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_VAD_INSERT_EVENT);
    HANDLE hEventVAD_REMOVE   = OpenEventW(EVENT_MODIFY_STATE, TRUE, MAPPING_NOTIFICATION_VAD_REMOVE_EVENT);
    if (!VadModifyArray || !hEventVAD_INSERT || !hEventVAD_REMOVE) {
        printf("[-] VAD modify setup failed: %lu\n", GetLastError()); return 1;
    }



	AddInitDataSection(sym_ctxNtskrnl);
	UpdateInitData(SymbolsArray, initSource, initTarget, 0, initVPN, 0);
	SetEvent(hEventINIT);

	ShowHelp();
	PrintStatus(initSource, initTarget);

	// Build CmdContext
    CmdContext ctx = {};
    if (initSource) { strncpy_s(ctx.sourceProcessBuf, initSource, _TRUNCATE); ctx.sourceProcess = ctx.sourceProcessBuf; }
    if (initTarget) { strncpy_s(ctx.targetProcessBuf, initTarget, _TRUNCATE); ctx.targetProcess = ctx.targetProcessBuf; }
    ctx.SymbolsArray        = SymbolsArray;
    ctx.VADArray            = VADArray;
    ctx.VADArrayFileName    = VADArrayFileName;
    ctx.WritePhysArray      = WritePhysArray;
    ctx.ReadPhysArray       = ReadPhysArray;
    ctx.VadModifyArray      = VadModifyArray;
    ctx.hEventUSERMODEREADY = hEventUSERMODEREADY;
    ctx.hEventLINK          = hEventLINK;
    ctx.hEventUnlink        = hEventUnlink;
    ctx.hEventINIT          = hEventINIT;
    ctx.hEventWRITE_PHYS    = hEventWRITE_PHYS;
    ctx.hEventREAD_PHYS     = hEventREAD_PHYS;
    ctx.hEventVAD_INSERT    = hEventVAD_INSERT;
    ctx.hEventVAD_REMOVE    = hEventVAD_REMOVE;
	ctx.sourceVA            = nullptr;
    ctx.targetVPN           = initVPN;
    ctx.targetVPNSize       = initVPNSize;

    // ---- flat command loop -------------------------------------------
    bool running = true;
	while (running) {
		printf("\nEnter command: "); fflush(stdout);
		int ch = _getch(); printf("%c\n", ch);

		switch (ch) {
		case '1': Cmd1Walk(&ctx);   break;
		case '2': Cmd2Print(&ctx);  break;
		case '3': printf("[*] '3' retired — use 'Q'.\n"); break;

		case 't': case 'T': CmdTTree(&ctx);    break;
		case 'n': case 'N': CmdNInsert(&ctx);  break;
		case 'd': case 'D': CmdDDelete(&ctx);  break;
		case 'v': case 'V': CmdVMapView(&ctx); break;
		case 'f': case 'F': CmdFFind(&ctx);    break;
		case 'z': case 'Z': CmdZDump(&ctx);    break;

		case 'e': case 'E': CmdEEdit(&ctx);      break;
		case 'q': case 'Q': CmdQRead(&ctx);      break;
		case 'w': case 'W': CmdWWritePhys(&ctx); break;
		case 'r': case 'R': CmdRReadPhys(&ctx);  break;
		case 'a': case 'A': CmdAProtect(&ctx);   break;
		case 'p': case 'P': CmdPScan(&ctx);      break;
		case '4':           Cmd4Link(&ctx);       break;

		case 'i': case 'I': CmdISource(&ctx); break;
		case 'o': case 'O': CmdOTarget(&ctx); break;

		case 'x': case 'X':
			printf("[*] Unlinking...\n");
			if (!SetEvent(ctx.hEventUnlink)) printf("[-] Failed: %lu\n", GetLastError());
			break;

		case 'm': case 'M': {
			char sb[32] = {}; int si = 0;
			printf("Memory view size (decimal or 0x hex): "); fflush(stdout);
			int mc;
			while ((mc = _getch()) != '\r' && mc != '\n') {
				if (mc == '\b') { if (si > 0) { sb[--si] = 0; printf("\b \b"); } }
				else if (si < 30 && (isdigit(mc) || mc=='x' || mc=='X' ||
						 (mc>='a'&&mc<='f') || (mc>='A'&&mc<='F')))
					{ sb[si++] = (char)mc; printf("%c", mc); }
			}
			sb[si] = 0; printf("\n");
			if (si > 0) {
				ctx.targetVPNSize = (size_t)strtoull(
					(strncmp(sb,"0x",2)==0 ? sb+2 : sb), NULL,
					(strncmp(sb,"0x",2)==0 ? 16 : 10));
				printf("[*] View size: %zu\n", ctx.targetVPNSize);
			}
			break;
		}

		case 'u': case 'U':
			printf("[*] 'U' retired — VPN entered inside '4','R','W'.\n");
			break;

		case '5':
			printf("[*] Exiting with cleanup...\n");
			running = false;
			break;

		case '6':
			printf("[*] Silent exit.\n");
			return 0;

		case '\r': case '\n':
			// bare Enter: reprint status without noise
			break;

		default:
			printf("Unknown command '%c'.\n", ch);
			ShowHelp();
			break;
		}

		if (running && ch != '6')
			PrintStatus(ctx.sourceProcess, ctx.targetProcess,
						(unsigned long long)ctx.sourceVA, ctx.targetVPN);
	}

    // Cleanup
    SetEvent(hEventUnlink);
    if (WritePhysArray)    UnmapViewOfFile(WritePhysArray);
    if (hWritePhysMapFile) CloseHandle(hWritePhysMapFile);
    if (hEventWRITE_PHYS)  CloseHandle(hEventWRITE_PHYS);
    if (ReadPhysArray)     UnmapViewOfFile(ReadPhysArray);
    if (hReadPhysMapFile)  CloseHandle(hReadPhysMapFile);
    if (hEventREAD_PHYS)   CloseHandle(hEventREAD_PHYS);
    if (VadModifyArray)    UnmapViewOfFile(VadModifyArray);
    if (hVadModifyMapFile) CloseHandle(hVadModifyMapFile);
    if (hEventVAD_INSERT)  CloseHandle(hEventVAD_INSERT);
    if (hEventVAD_REMOVE)  CloseHandle(hEventVAD_REMOVE);
    return 0;
}
