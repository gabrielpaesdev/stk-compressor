#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "codec.h"

#define VERSION_INFO "SimpleTextKompressor Release v1.1.0 (March 19, 2026) — 26.5 kB © Gabriel Paes <gabrielpaesdev@proton.me>"

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


void print_usage() {
    printf("%s\n\n", VERSION_INFO);
    printf("Usage:\n");
    printf("  Compress:   ./stk -c <input.txt> -o <output.stk> [--password <password>]\n");
    printf("  Decompress: ./stk -d <input.stk> -o <output.txt> [--password <password>]\n");
    printf("  Version:    ./stk -v\n");
}

int main(int argc, char *argv[]) {
    int mode = 0; // 1 = Compress, 2 = Decompress
    char *input = NULL;
    char *output = NULL;
    char *password = NULL;


    static struct option long_options[] = {
        {"password", required_argument, 0, 'p'},
        {0, 0, 0, 0} 
    };

    int opt;
    int option_index = 0;



    while ((opt = getopt_long(argc, argv, "vc:d:o:p:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v':
                print_usage();
                return 0;
            case 'c':
                mode = 1;
                input = optarg; 
                break;
            case 'd':
                mode = 2;
                input = optarg;
                break;
            case 'o':
                output = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case '?': 
            default:
                print_usage();
                return 1;
        }
    }


    if (mode == 0 || input == NULL || output == NULL) {
        fprintf(stderr, "Error: Missing required arguments.\n\n");
        print_usage();
        return 1;
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
    }

    free(final_output);
    return 0;
}
