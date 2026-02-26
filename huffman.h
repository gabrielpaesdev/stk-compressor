#ifndef HUFFMAN_H
#define HUFFMAN_H

typedef struct Node {
    int ch;
    int freq;
    struct Node *left;
    struct Node *right;
} Node;

Node* create_node(int ch, int freq, Node *left, Node *right);
void free_tree(Node *n);
Node* build_tree(int *freq);
void generate_codes(Node *n, char *current_code, int depth, char codes[256][256]);
void insert_huffman_node(Node **root, int ch, const char *code);

#endif // HUFFMAN_H
