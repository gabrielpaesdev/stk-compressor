# STK - SimpleTextKompressor

A command-line file compressor and decompressor written in C, featuring Huffman coding and optional encryption.

### Features

* File compression and decompression using Huffman coding algorithms.
* Optional secure encryption and decryption using AES-256-GCM and Argon2id key derivation..
* Command-line interface with easy mode selection (Compress / Decompress).

### Compilation

Requires GCC, OpenSSL (`libssl-dev`), and Argon2 (`libargon2-dev`) installed on your system.

To compile the program, run the following command in your terminal:

```bash
gcc main.c codec.c huffman.c buffer.c -o stk -lssl -lcrypto -largon2

```

### Usage

Run the binary with `-v` to see version information, or use the following syntax to compress and decompress files:

**Compress a file:**

```bash
./stk 1 input.txt output.stk [--password <password>]

```

**Decompress a file:**

```bash
./stk 2 input.stk output.txt [--password <password>]

```

