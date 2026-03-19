# STK - SimpleTextKompressor

A command-line file compressor and decompressor written in C. It features lossless compression using Huffman coding algorithms and offers optional, secure file encryption.

### ✨ Features

* **Efficient Compression:** Lossless file compression and decompression using Huffman coding.
* **Secure Encryption (Optional):** Military-grade encryption using AES-256-GCM and Argon2id key derivation for password protection.
* **Modern CLI:** POSIX-compliant command-line interface with intuitive flags for easy integration into scripts and daily workflows.

### 🛠️ Prerequisites

To compile STK, you will need `gcc`, `make`, OpenSSL, and Argon2 installed on your system. 

On Debian/Ubuntu-based systems, you can install the dependencies running:
```bash
sudo apt update
sudo apt install gcc make libssl-dev libargon2-dev
```

### 🚀 Compilation

STK comes with a `Makefile` for streamlined compilation. Simply navigate to the project directory and run:

```bash
make
```
*(To clean up the compiled object files and the executable, you can run `make clean`).*

### 💻 Usage

Run the binary with `-v` to see version information, or use the following syntax to compress and decompress files. The argument order is fully flexible.

**Compress a file:**
```bash
./stk -c input.txt -o output.stk [--password "your_secure_password"]
```

**Decompress a file:**
```bash
./stk -d input.stk -o output.txt [--password "your_secure_password"]
```

**Check Version & Help:**
```bash
./stk -v
```

### ⚠️ Known Behavior

**Small Files Overhead:** Due to the metadata header (Huffman tree dictionary) required to rebuild the file during decompression, compressing very small files (under ~2 KB) may result in an output file slightly larger than the original. STK's compression algorithm reaches its true efficiency and reduces file sizes effectively on files that exceed this threshold.

### 📄 License

[cite_start]This project is licensed under the MIT License[cite: 1]. See the `LICENSE` file for details.

