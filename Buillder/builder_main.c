#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
	const char* inputFileName = "original.exe";
	const char* outputFileName = "payload.enc";
	char* key = "mysecretkey";

	FILE* inFile = fopen(inputFileName, "rb");

	if (!inFile) {
		printf("Error opening input file.\n");
		return 1;
	}

	// find file size
	fseek(inFile, 0, SEEK_END);
	long fileSize = ftell(inFile);
	fseek(inFile, 0, SEEK_SET); // go back to beginning

	// malloc and read file into buffer
	unsigned char* buffer = (unsigned char*)malloc(fileSize);
	if (!buffer) {
		printf("Memory allocation failed.\n");
		fclose(inFile);
		return 1;
	}

	fread(buffer, 1, fileSize, inFile);
	fclose(inFile);

	printf("Read %ld bytes from %s\n", fileSize, inputFileName);

	XorCipher(buffer, fileSize, key, strlen(key));

	FILE* outFile = fopen(outputFileName, "wb");
	if (!outFile) {
		printf("Error opening output file.\n");
		free(buffer);
		return 1;
	}
	fwrite(buffer, 1, fileSize, outFile);
	fclose(outFile);
	free(buffer);
	printf("Encrypted data written to %s\n", outputFileName);

	return 0;
}