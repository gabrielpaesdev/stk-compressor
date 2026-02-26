#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec.h"

#define VERSION_INFO "SimpleTextKompressor Release v1.0.0 (February 26, 2026) — 26.4 kB © Gabriel Paes <gabrielpaesdev@proton.me>"

int has_extension(const char *filename, const char *ext) {
    size_t len = strlen(filename);
    size_t ext_len = strlen(ext);
    if (len < ext_len) return 0;
    return strcmp(filename + len - ext_len, ext) == 0;
}

char* ensure_stk_extension(const char *filename) {
    if (has_extension(filename, ".stk")) {
        return strdup(filename);
    } else {
        size_t len = strlen(filename);
        char *newname = malloc(len + 5); 
        if (!newname) {
            fprintf(stderr, "Error: memory allocation failed\n");
            exit(1);
        }
        strcpy(newname, filename);
        strcat(newname, ".stk");
        return newname;
    }
}

int main(int argc, char *argv[]) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-v") == 0)) {
        printf("%s\n", VERSION_INFO);
        printf("\nUsage:\n");
        printf("  Compress:   ./cstk 1 input.txt output.stk   [--password <password>]\n");
        printf("  Decompress: ./cstk 2 input.stk output.txt   [--password <password>]\n");
        return 0;
    }

    if (argc < 4) {
        printf("Invalid usage!\n");
        printf("Run './cstk -v' to see version and usage info.\n");
        return 1;
    }

    int mode = atoi(argv[1]);
    char *input = argv[2];
    char *output = argv[3];
    char *password = NULL;

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            password = argv[i + 1];
            break;
        }
    }

    char *final_output;
    if (mode == 1) { 
        final_output = ensure_stk_extension(output);
    } else {
        final_output = strdup(output); 
    }

    if (mode == 1) {
        compress(input, final_output, password);
        printf("File compressed successfully to '%s'\n", final_output);
    } else if (mode == 2) {
        decompress(input, final_output, password);
        printf("File decompressed successfully to '%s'\n", final_output);
    } else {
        printf("Invalid mode. Use 1 for compress and 2 for decompress.\n");
        free(final_output);
        return 1;
    }

    free(final_output);
    return 0;
}
