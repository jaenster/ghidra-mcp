/**
 * Deep call chain for testing call graph traversal
 *
 * Expected call graph:
 * main -> level1 -> level2 -> level3 -> level4 -> leaf_function
 *
 * Also has branching:
 * main -> branch_a -> common_helper
 * main -> branch_b -> common_helper
 */

#include <stdio.h>

// Leaf function at the bottom of the call chain
int leaf_function(int value) {
    return value * 2;
}

int level4(int x) {
    printf("Level 4: %d\n", x);
    return leaf_function(x + 4);
}

int level3(int x) {
    printf("Level 3: %d\n", x);
    return level4(x + 3);
}

int level2(int x) {
    printf("Level 2: %d\n", x);
    return level3(x + 2);
}

int level1(int x) {
    printf("Level 1: %d\n", x);
    return level2(x + 1);
}

// Common helper called from multiple places
int common_helper(int a, int b) {
    return a * b + 42;
}

int branch_a(int x) {
    printf("Branch A\n");
    return common_helper(x, 10);
}

int branch_b(int x) {
    printf("Branch B\n");
    return common_helper(x, 20);
}

int main(int argc, char** argv) {
    int deep_result = level1(0);
    printf("Deep chain result: %d\n", deep_result);

    int a_result = branch_a(5);
    int b_result = branch_b(5);
    printf("Branch results: %d, %d\n", a_result, b_result);

    return 0;
}
