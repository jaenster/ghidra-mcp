/**
 * Test binary for import/export analysis
 *
 * Expected imports (varies by platform):
 * - printf, puts, malloc, free, memcpy, strlen, fopen, fclose, fread
 *
 * Expected exports (when compiled as shared lib):
 * - exported_function_1, exported_function_2, get_library_version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// These would be exports if compiled as shared library
__attribute__((visibility("default")))
int exported_function_1(int x) {
    return x * 2;
}

__attribute__((visibility("default")))
int exported_function_2(const char* str) {
    return (int)strlen(str);
}

__attribute__((visibility("default")))
const char* get_library_version(void) {
    return "1.0.0-test";
}

// Internal helper (not exported)
static int internal_helper(int a, int b) {
    return a + b;
}

// Function using many libc imports
void use_many_imports(void) {
    // Memory
    void* ptr = malloc(1024);
    memcpy(ptr, "test data", 10);
    free(ptr);

    // Strings
    char buf[100];
    strcpy(buf, "Hello");
    strcat(buf, " World");
    size_t len = strlen(buf);
    printf("String: %s (len=%zu)\n", buf, len);

    // File I/O
    FILE* f = fopen("/dev/null", "r");
    if (f) {
        char data[32];
        fread(data, 1, 32, f);
        fclose(f);
    }

    // More string ops
    puts("Done with imports test");
}

int main(int argc, char** argv) {
    printf("Testing imports/exports\n");

    int r1 = exported_function_1(21);
    int r2 = exported_function_2("hello");
    const char* ver = get_library_version();

    printf("Results: %d, %d, %s\n", r1, r2, ver);

    use_many_imports();

    return internal_helper(r1, r2);
}
