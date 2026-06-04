/**
 * Simple test binary with predictable characteristics
 *
 * Expected findings:
 * - Functions: main, add_numbers, multiply_numbers, process_data
 * - Strings: "Hello from test binary!", "Result: %d", "SECRET_KEY_12345"
 * - Call graph: main -> process_data -> add_numbers, multiply_numbers
 * - Imports: printf, puts
 */

#include <stdio.h>
#include <string.h>

// Simple arithmetic - should decompile cleanly
int add_numbers(int a, int b) {
    return a + b;
}

int multiply_numbers(int a, int b) {
    return a * b;
}

// Uses both helpers - creates call graph
int process_data(int x, int y) {
    int sum = add_numbers(x, y);
    int product = multiply_numbers(x, y);
    return sum + product;
}

// String that should be findable
const char* get_secret(void) {
    return "SECRET_KEY_12345";
}

// XOR pattern - slightly suspicious
void xor_buffer(unsigned char* buf, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

int main(int argc, char** argv) {
    puts("Hello from test binary!");

    int result = process_data(10, 20);
    printf("Result: %d\n", result);

    // Use the secret so it's not optimized out
    const char* secret = get_secret();
    printf("Secret length: %zu\n", strlen(secret));

    // XOR something
    unsigned char data[16] = {0x41, 0x42, 0x43, 0x44};
    xor_buffer(data, 4, 0x55);

    return result > 100 ? 0 : 1;
}
