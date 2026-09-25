#include <Windows.h>
#include <stdio.h>
#include <memoryapi.h>
#include <time.h>



DWORD RvaToOffset(DWORD rva, PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);

	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (rva >= section[i].VirtualAddress &&
			rva < section[i].VirtualAddress + section[i].SizeOfRawData)
		{
			return section[i].PointerToRawData +
				(rva - section[i].VirtualAddress);
		}
	}

	return rva;
}



BOOL Parse_PE(HANDLE hFile, LPCSTR lpPeName) {

	BOOL bSTATE = FALSE;
	HANDLE hMapping = NULL;
	PBYTE pAddress = NULL;


	hFile = CreateFileA(lpPeName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == NULL) {
		printf("[!] CreateFileA failed with error %lu \n", GetLastError());
		bSTATE = FALSE; goto cleanup;
	}

	// make section object for that file -- Which first registration step
	hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL) {
		printf("[!] CreateFileMappingA failed with error %lu \n", GetLastError());
		bSTATE = FALSE; goto cleanup;
	}


	// needing that addres
	pAddress = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (pAddress == NULL) {
		bSTATE = FALSE; goto cleanup;
	}


	// get the DOS header from the address
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Invalid DOS Signature"); bSTATE = FALSE; goto cleanup;
	}

	printf("[#] Retrived Valid DOS signature...Processing PE file...\n");
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pAddress + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] Invalid Nt Signature ..\n"); bSTATE = FALSE; goto cleanup;
	}


	printf("[-] Analysing FILE HEADER \n");
	// File Header
	IMAGE_FILE_HEADER pFileHeader = pNtHeaders->FileHeader;

	if (pFileHeader.Machine == 0x014C) { printf("\t\t[#] Machine Type is x86 / i386 \n"); }
	else if (pFileHeader.Machine == 0x8664) { printf("\t\t[#] Machine Type is AMD64 / x64\n"); }
	else if (pFileHeader.Machine == 0xAA64) { printf("\t\t[#] Machine Type is ARM64 \n"); }
	else if (pFileHeader.Machine == 0x01C0) { printf("[#] Machine type is ARM \n"); }
	else if (pFileHeader.Machine == 0x0200) { printf("[#] Machine Type is Intel ltanium"); }
	else { printf("\t\t[!] Ummmm !!!...wHAT IS tHe MAChinE TypE ?? \n"); }

	time_t timestamp = (time_t)pFileHeader.TimeDateStamp;
	printf("\t\t[#] Creation Date is [  %s  ]\n", ctime(&timestamp));
	printf("\t\t[#] PE FileHeader Characteristics is [  0x%04X  ] \n\n", pFileHeader.Characteristics);


	printf("[-] Analysing OPTIONAL HEADER \n");
	printf("\t\t[#] Address of Entry point is [  0x%08X  ]\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t\t[#] Major OS Version is [  %u.%u  ]\n",
		pNtHeaders->OptionalHeader.MajorOperatingSystemVersion,
		pNtHeaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t\t[#] Size of code is [  %u bytes (%.2f KB)  ]\n",
		pNtHeaders->OptionalHeader.SizeOfCode,
		pNtHeaders->OptionalHeader.SizeOfCode / 1024.0);

	printf("\t\t[#] Size of Initialized Data [  %u bytes (%.2f KB)  ]\n",
		pNtHeaders->OptionalHeader.SizeOfInitializedData,
		pNtHeaders->OptionalHeader.SizeOfInitializedData / 1024.0);

	printf("\t\t[#] Size of Uninitialized Data [  %u bytes (%.2f KB)  ]\n",
		pNtHeaders->OptionalHeader.SizeOfUninitializedData,
		pNtHeaders->OptionalHeader.SizeOfUninitializedData / 1024.0);


	//PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPE + ImageOPTHdr.DataDirecotry[____EXPORT____].VirtualAddress);
	printf("[-] Analysing Data Directory HEADER \n");
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pNtHeaders->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		printf("[!] Invalid Optional Signature"); bSTATE = FALSE; goto cleanup;
	}
 

	if (ImgOptHdr.Magic == 0x10B) { printf("\t\t[#] Magic Characteristic is PE32\n"); }
	else if (ImgOptHdr.Magic == 0x20B) { printf("\t\t[#] Magic Characteristic is PE32+ / 64 Bit\n"); }
	else if (ImgOptHdr.Magic == 0x107) { printf("\t\t[#] Magic Characteristic is a ROM Image \n"); }
	else { printf("\t\t[!] Ummmm !!!...wHAT ...Where did you bRinG this MAGic ?? \n"); }

	// ImgOptHdr.Subsystem -- 0x%04X
	if (ImgOptHdr.Subsystem == 0) { printf("\t\t[#] SubSystem is Unknown\n"); }
	else if (ImgOptHdr.Subsystem == 1) { printf("\t\t[#] SubSystem is Native \n"); }
	else if (ImgOptHdr.Subsystem == 2) { printf("\t\t[#] SubSystem is Windows GUI\n"); }
	else if (ImgOptHdr.Subsystem == 3) { printf("\t\t[#] SubSystem is Windows GUI / Console\n"); }
	else { printf("\t\t[!] Ummmm !!!...wHAT ..There is no option for the following..sorry ?? \n"); }


	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pAddress + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	printf("\t\t[#] Number of function used from the export table  [  %u  ]\n", pImgExportDir->NumberOfFunctions);
	// AddressOfFunctions is an RVA from pAddress, NOT from pImgExportDir
	DWORD* AddressOfFunctions = (DWORD*)(pAddress + pImgExportDir->AddressOfFunctions);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		printf("\t\t\t[#] Address of the function as follows [  0x%08X  ]\n", AddressOfFunctions[i]);
	}

	DWORD ImportOffset = RvaToOffset(
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		pNtHeaders
	);
	PIMAGE_IMPORT_DESCRIPTOR pImgImportDir =
		(PIMAGE_IMPORT_DESCRIPTOR)(pAddress + ImportOffset);

	while (pImgImportDir->Name) {
		char* DllName = (char*)(pAddress + RvaToOffset(
			pImgImportDir->Name,
			pNtHeaders
		));
		printf("\t\t[#] Imported DLL: [ %s ]\n", DllName);
		pImgImportDir++;
	}


	DWORD ThunkRva = pImgImportDir->OriginalFirstThunk;
	if (!ThunkRva)
		ThunkRva = pImgImportDir->FirstThunk;

	PIMAGE_THUNK_DATA64 thunk =
		(PIMAGE_THUNK_DATA64)(pAddress + RvaToOffset(ThunkRva, pNtHeaders));

	while (thunk->u1.AddressOfData) {
		if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
		{
			PIMAGE_IMPORT_BY_NAME importName =
				(PIMAGE_IMPORT_BY_NAME)(pAddress +
					RvaToOffset((DWORD)thunk->u1.AddressOfData, pNtHeaders));

			printf("\t\t\t[#] Function: [ %s ]\n",
				importName->Name);
		}
		else
		{
			printf("\t\t\t[#] Function: [ Ordinal %llu ]\n",
				thunk->u1.Ordinal & 0xFFFF);
		}

		thunk++;
	}



	// SECTIONS HEADER - skip past ntHeadr
	PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHeaders);
	WORD SectionNumbers = pNtHeaders->FileHeader.NumberOfSections;

	for (int j = 0; j < pNtHeaders->FileHeader.NumberOfSections; j++) {
		// section Name is exactly 8 bytes and may not be NULL terminated
		printf("\t\t[#] %d// Section Name:   %.*s\n", j, IMAGE_SIZEOF_SHORT_NAME, pSectionHdr[j].Name);
		printf("\t\t[#] %d// Section VA: 0x%08X    |     Size of raw Raw Data:  0x%08X\n",
			j,
			pSectionHdr[j].VirtualAddress,
			pSectionHdr[j].SizeOfRawData);
	}


	bSTATE = TRUE;


cleanup:
	if (hMapping) {
		CloseHandle(hMapping);
	}
	return bSTATE;
}



int main(int argc, char* argv[]) {

	HANDLE hFile = NULL;

	if (argc != 2) {
		printf("[!] Usage:  ./Within_Pe.exe    <Pe_Target_File.exe>  \n");
		return 1;
	}

	if (!Parse_PE(hFile, argv[1])) {
		printf("[!] Parse_PE failed with error %lu \n", GetLastError());
		goto cleanup;
	}
	printf("[+] DONE!!\n");
	cleanup:
	if (hFile) {
		CloseHandle(hFile);
	}
	return 0;
}