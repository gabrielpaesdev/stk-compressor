#include "huffman.h"
#include <stdlib.h>
#include <string.h>

Node* create_node(int ch, int freq, Node *left, Node *right) {
    Node *n = (Node*)malloc(sizeof(Node));
    n->ch = ch; n->freq = freq; n->left = left; n->right = right;
    return n;
}

void free_tree(Node *n) {
    if (!n) return;
    free_tree(n->left);
    free_tree(n->right);
    free(n);
}


static int compare_nodes(const void *a, const void *b) {
    Node *n1 = *(Node**)a;
    Node *n2 = *(Node**)b;
    return n2->freq - n1->freq; 
}

Node* build_tree(int *freq) {
    Node *nodes[256];
    int count = 0;
    
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            nodes[count++] = create_node(i, freq[i], NULL, NULL);
        }
    }

    if (count == 0) return NULL;

    while (count > 1) {
        qsort(nodes, count, sizeof(Node*), compare_nodes);
        Node *a = nodes[count - 1]; 
        Node *b = nodes[count - 2]; 
        
        Node *parent = create_node(-1, a->freq + b->freq, a, b);
        nodes[count - 2] = parent;
        count--;
    }
    return nodes[0];
}

void generate_codes(Node *n, char *current_code, int depth, char codes[256][256]) {
    if (!n) return;
    
    if (!n->left && !n->right) {
        if (depth == 0) {
            strcpy(codes[n->ch], "0");
        } else {
            current_code[depth] = '\0';
            strcpy(codes[n->ch], current_code);
        }
        return;
    }
    
    current_code[depth] = '0';
    generate_codes(n->left, current_code, depth + 1, codes);
    
    current_code[depth] = '1';
    generate_codes(n->right, current_code, depth + 1, codes);
}

void insert_huffman_node(Node **root, int ch, const char *code) {
    if (*root == NULL) *root = create_node(-1, 0, NULL, NULL);
    Node *curr = *root;
    
    for (int i = 0; code[i] != '\0'; i++) {
        if (code[i] == '0') {
            if (curr->left == NULL) curr->left = create_node(-1, 0, NULL, NULL);
            curr = curr->left;
        } else if (code[i] == '1') {
            if (curr->right == NULL) curr->right = create_node(-1, 0, NULL, NULL);
            curr = curr->right;
        }
    }
    curr->ch = ch;
}
