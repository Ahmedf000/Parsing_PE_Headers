/*
format specifficer for PE processing as no resources out there lol

PE PARSER — C / VISUAL STUDIO REFERENCE


============================================================
 DOS HEADER — IMAGE_DOS_HEADER
============================================================

| Field | Type | Format   |
|------------ - | ------ | ----------|
| e_magic | WORD | 0x % 04X   |
| e_cblp | WORD | 0x % 04X   |
| e_cp | WORD | % u       |
| e_crlc | WORD | % u       |
| e_cparhdr | WORD | % u       |
| e_minalloc | WORD | 0x % 04X   |
| e_maxalloc | WORD | 0x % 04X   |
| e_ss | WORD | 0x % 04X   |
| e_sp | WORD | 0x % 04X   |
| e_lfarlc | WORD | 0x % 04X   |
| e_lfanew | LONG | 0x % 08X   |

============================================================
 PE / COFF HEADER — IMAGE_FILE_HEADER
============================================================

| Field | Type | Format   |
|-------------------------- | ------ - | ----------|
| PE Signature | DWORD | 0x % 08X  |
| Machine | WORD | 0x % 04X  |
| NumberOfSections | WORD | % u      |
| TimeDateStamp | DWORD | 0x % 08X  |
| PointerToSymbolTable | DWORD | 0x % 08X  |
| NumberOfSymbols | DWORD | % u      |
| SizeOfOptionalHeader | WORD | % u      |
| Characteristics | WORD | 0x % 04X  |

============================================================
 PE32 + OPTIONAL HEADER — IMAGE_OPTIONAL_HEADER64
============================================================

| Field | Type | Format        |
|---------------------------- - | ------------ | -------------- - |
| Magic | WORD | 0x % 04X        |
| MajorLinkerVersion | BYTE | % u            |
| MinorLinkerVersion | BYTE | % u            |
| SizeOfCode | DWORD | 0x % 08X        |
| SizeOfInitializedData | DWORD | 0x % 08X        |
| SizeOfUninitializedData | DWORD | 0x % 08X        |
| AddressOfEntryPoint | DWORD | 0x % 08X        |
| BaseOfCode | DWORD | 0x % 08X        |
| ImageBase | ULONGLONG | 0x % 016llX     |
| SectionAlignment | DWORD | 0x % 08X        |
| FileAlignment | DWORD | 0x % 08X        |
| MajorOperatingSystemVersion | WORD | % u            |
| MinorOperatingSystemVersion | WORD | % u            |
| MajorImageVersion | WORD | % u            |
| MinorImageVersion | WORD | % u            |
| MajorSubsystemVersion | WORD | % u            |
| MinorSubsystemVersion | WORD | % u            |
| Win32VersionValue | DWORD | 0x % 08X        |
| SizeOfImage | DWORD | 0x % 08X        |
| SizeOfHeaders | DWORD | 0x % 08X        |
| CheckSum | DWORD | 0x % 08X        |
| Subsystem | WORD | 0x % 04X        |
| DllCharacteristics | WORD | 0x % 04X        |
| SizeOfStackReserve | ULONGLONG | 0x % 016llX     |
| SizeOfStackCommit | ULONGLONG | 0x % 016llX     |
| SizeOfHeapReserve | ULONGLONG | 0x % 016llX     |
| SizeOfHeapCommit | ULONGLONG | 0x % 016llX     |
| LoaderFlags | DWORD | 0x % 08X        |
| NumberOfRvaAndSizes | DWORD | % u            |

============================================================
 VERSION FIELDS
============================================================

Linker Version :
% u. % u

Target OS Version :
% u. % u

Image Version :
% u. % u

Subsystem Version :
% u. % u

============================================================
 DATA DIRECTORY — IMAGE_DATA_DIRECTORY
============================================================

| Field | Type | Format   |
|---------------- - | ------ - | ----------|
| VirtualAddress | DWORD | 0x % 08X  |
| Size | DWORD | 0x % 08X |


============================================================
SECTION HEADER — IMAGE_SECTION_HEADER
============================================================

| Field | Type | Format              |
|-------------------------- | ---------- - | -------------------- - |
| Name | BYTE[8] | fixed 8 - byte string |
| VirtualSize | DWORD | 0x % 08X             |
| VirtualAddress | DWORD | 0x % 08X             |
| SizeOfRawData | DWORD | 0x % 08X             |
| PointerToRawData | DWORD | 0x % 08X             |
| PointerToRelocations | DWORD | 0x % 08X             |
| PointerToLinenumbers | DWORD | 0x % 08X             |
| NumberOfRelocations | WORD | % u                 |
| NumberOfLinenumbers | WORD | % u                 |
| Characteristics | DWORD | 0x % 08X             |

============================================================
IMPORT DIRECTORY — IMAGE_IMPORT_DESCRIPTOR
============================================================

| Field | Type | Format   |
|---------------------- | ------ - | ----------|
| OriginalFirstThunk | DWORD | 0x % 08X  |
| TimeDateStamp | DWORD | 0x % 08X  |
| ForwarderChain | DWORD | 0x % 08X  |
| Name | DWORD | 0x % 08X  |
| FirstThunk | DWORD | 0x % 08X |


============================================================
 EXPORT DIRECTORY — IMAGE_EXPORT_DIRECTORY
============================================================

| Field | Type | Format   |
|-------------------------- | ------ - | ----------|
| Characteristics | DWORD | 0x % 08X  |
| TimeDateStamp | DWORD | 0x % 08X  |
| MajorVersion | WORD | % u      |
| MinorVersion | WORD | % u      |
| Name | DWORD | 0x % 08X  |
| Base | DWORD | % u      |
| NumberOfFunctions | DWORD | % u      |
| NumberOfNames | DWORD | % u      |
| AddressOfFunctions | DWORD | 0x % 08X  |
| AddressOfNames | DWORD | 0x % 08X  |
| AddressOfNameOrdinals | DWORD | 0x % 08X |

*/