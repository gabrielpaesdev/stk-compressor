#ifndef CODEC_H
#define CODEC_H

void compress(const char *input_file, const char *output_file, const char *password);
void decompress(const char *input_file, const char *output_file, const char *password);

#endif // CODEC_H
