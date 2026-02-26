#include "codec.h"
#include "buffer.h"
#include "huffman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>

static void pack_bits(const char *bit_str, ByteBuffer *out_bytes, uint8_t *out_padding) {
    uint8_t current = 0;
    int count = 0;
    while (*bit_str) {
        current <<= 1;
        if (*bit_str == '1') current |= 1;
        count++;
        if (count == 8) {
            buf_append(out_bytes, &current, 1);
            current = 0;
            count = 0;
        }
        bit_str++;
    }
    *out_padding = 0;
    if (count > 0) {
        *out_padding = (uint8_t)(8 - count);
        current <<= *out_padding;
        buf_append(out_bytes, &current, 1);
    }
}

static void unpack_bits(const uint8_t *data, size_t size, uint8_t padding, ByteBuffer *out_bits) {
    if (size == 0) return;
    for (size_t i = 0; i < size; i++) {
        int bits_to_read = (i == size - 1) ? (8 - padding) : 8;
        for (int j = 7; j >= 8 - bits_to_read; j--) {
            char bit = ((data[i] >> j) & 1) ? '1' : '0';
            buf_append(out_bits, &bit, 1);
        }
    }
    char null_term = '\0';
    buf_append(out_bits, &null_term, 1);
}

static int encrypt_data(const uint8_t *plaintext, size_t pt_len, const char *password, ByteBuffer *out) {
    uint8_t salt[16], nonce[12], key[32];
    RAND_bytes(salt, sizeof(salt));
    RAND_bytes(nonce, sizeof(nonce));
    if (argon2id_hash_raw(2, 16384, 2, password, strlen(password), salt, sizeof(salt), key, sizeof(key)) != ARGON2_OK) {
        return 0;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    uint8_t *ciphertext = malloc(pt_len + 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    buf_append(out, salt, sizeof(salt));
    buf_append(out, nonce, sizeof(nonce));
    buf_append(out, ciphertext, ciphertext_len);
    buf_append(out, tag, sizeof(tag));
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static int decrypt_data(const uint8_t *data, size_t data_len, const char *password, ByteBuffer *out) {
    if (data_len < 44) return 0;
    const uint8_t *salt = data;
    const uint8_t *nonce = data + 16;
    const uint8_t *ciphertext = data + 28;
    size_t ciphertext_len = data_len - 28 - 16;
    const uint8_t *tag = data + data_len - 16;
    uint8_t key[32];
    if (argon2id_hash_raw(2, 16384, 2, password, strlen(password), salt, 16, key, sizeof(key)) != ARGON2_OK) {
        return 0;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t *plaintext = malloc(ciphertext_len);
    int len, plaintext_len, ret;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) {
        plaintext_len += len;
        buf_append(out, plaintext, plaintext_len);
        free(plaintext);
        return 1;
    } else {
        free(plaintext);
        return 0;
    }
}

void compress(const char *input_file, const char *output_file, const char *password) {
    FILE *f = fopen(input_file, "rb");
    if (!f) { printf("Error reading input file.\n"); return; }
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize == 0) { printf("Input file is empty.\n"); fclose(f); return; }
    uint8_t *text = malloc(fsize);
    fread(text, 1, fsize, f);
    fclose(f);

    int freq[256] = {0};
    for (size_t i = 0; i < fsize; i++) freq[text[i]]++;

    Node *tree = build_tree(freq);
    char codes[256][256] = {{0}};
    char temp_code[256];
    generate_codes(tree, temp_code, 0, codes);

    ByteBuffer encoded_str;
    buf_init(&encoded_str);
    for (size_t i = 0; i < fsize; i++) {
        buf_append(&encoded_str, codes[text[i]], strlen(codes[text[i]]));
    }
    char null_term = '\0';
    buf_append(&encoded_str, &null_term, 1);

    ByteBuffer packed_bytes;
    buf_init(&packed_bytes);
    uint8_t padding;
    pack_bits((char*)encoded_str.data, &packed_bytes, &padding);

    ByteBuffer buf;
    buf_init(&buf);
    uint32_t dict_size = 0;
    for (int i = 0; i < 256; i++) if (strlen(codes[i]) > 0) dict_size++;
    buf_append(&buf, &dict_size, 4);
    buf_append(&buf, &padding, 1);

    for (int i = 0; i < 256; i++) {
        if (strlen(codes[i]) > 0) {
            int32_t char_val = i;
            uint8_t code_len = strlen(codes[i]);
            buf_append(&buf, &char_val, 4);
            buf_append(&buf, &code_len, 1);
            buf_append(&buf, codes[i], code_len);
        }
    }

    buf_append(&buf, packed_bytes.data, packed_bytes.size);

    ByteBuffer final_data;
    buf_init(&final_data);

    if (password && strlen(password) > 0) {
        if (!encrypt_data(buf.data, buf.size, password, &final_data)) {
            printf("Error encrypting data.\n");
            goto cleanup;
        }
        printf("File encrypted successfully.\n");
    } else {
        buf_append(&final_data, buf.data, buf.size);
    }

    FILE *out = fopen(output_file, "wb");
    fwrite(final_data.data, 1, final_data.size, out);
    fclose(out);
    printf("File compressed: %s\n", output_file);

cleanup:
    free(text); free_tree(tree);
    buf_free(&encoded_str); buf_free(&packed_bytes);
    buf_free(&buf); buf_free(&final_data);
}

void decompress(const char *input_file, const char *output_file, const char *password) {
    FILE *f = fopen(input_file, "rb");
    if (!f) { printf("Error opening compressed file.\n"); return; }
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize == 0) { printf("Compressed file is empty.\n"); fclose(f); return; }

    uint8_t *file_data = malloc(fsize);
    fread(file_data, 1, fsize, f);
    fclose(f);

    ByteBuffer payload;
    buf_init(&payload);

    if (password && strlen(password) > 0) {
        if (!decrypt_data(file_data, fsize, password, &payload)) {
            printf("Error: wrong password or corrupted file.\n");
            free(file_data); buf_free(&payload);
            return;
        }
        printf("File decrypted successfully.\n");
    } else {
        buf_append(&payload, file_data, fsize);
    }
    free(file_data);

    if (payload.size < 5) {
        printf("Error: invalid file format.\n");
        buf_free(&payload);
        return;
    }

    size_t offset = 0;
    uint32_t dict_size;
    memcpy(&dict_size, payload.data + offset, 4); offset += 4;
    uint8_t padding;
    memcpy(&padding, payload.data + offset, 1); offset += 1;

    Node *root = NULL;
    for (uint32_t i = 0; i < dict_size; i++) {
        if (offset >= payload.size) break;
        int32_t char_val;
        memcpy(&char_val, payload.data + offset, 4); offset += 4;
        uint8_t code_len;
        memcpy(&code_len, payload.data + offset, 1); offset += 1;
        char code_str[256] = {0};
        memcpy(code_str, payload.data + offset, code_len); offset += code_len;
        insert_huffman_node(&root, char_val, code_str);
    }

    size_t compressed_size = payload.size - offset;
    uint8_t *compressed_data = payload.data + offset;

    ByteBuffer bit_str;
    buf_init(&bit_str);
    unpack_bits(compressed_data, compressed_size, padding, &bit_str);

    ByteBuffer out_text;
    buf_init(&out_text);

    Node *curr = root;
    char *bits = (char*)bit_str.data;
    for (size_t i = 0; i < bit_str.size - 1; i++) {
        if (bits[i] == '0') curr = curr->left;
        else if (bits[i] == '1') curr = curr->right;
        if (!curr->left && !curr->right) {
            uint8_t c = (uint8_t)curr->ch;
            buf_append(&out_text, &c, 1);
            curr = root;
        }
    }

    FILE *out = fopen(output_file, "wb");
    if (out) {
        fwrite(out_text.data, 1, out_text.size, out);
        fclose(out);
        printf("File decompressed: %s\n", output_file);
    } else {
        printf("Error creating output file.\n");
    }

    free_tree(root);
    buf_free(&payload);
    buf_free(&bit_str);
    buf_free(&out_text);
}
