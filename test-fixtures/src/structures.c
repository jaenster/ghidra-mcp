/**
 * Test binary with structures for data type analysis
 *
 * Expected structures:
 * - Point: { int x, int y } (8 bytes)
 * - Rectangle: { Point top_left, Point bottom_right } (16 bytes)
 * - Person: { char name[32], int age, float height } (40 bytes)
 * - LinkedNode: { int value, LinkedNode* next } (16 bytes on 64-bit)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int x;
    int y;
} Point;

typedef struct {
    Point top_left;
    Point bottom_right;
} Rectangle;

typedef struct {
    char name[32];
    int age;
    float height;
} Person;

typedef struct LinkedNode {
    int value;
    struct LinkedNode* next;
} LinkedNode;

// Functions that use these structures

Point make_point(int x, int y) {
    Point p;
    p.x = x;
    p.y = y;
    return p;
}

int rectangle_area(Rectangle* rect) {
    int width = rect->bottom_right.x - rect->top_left.x;
    int height = rect->bottom_right.y - rect->top_left.y;
    return width * height;
}

void print_person(Person* p) {
    printf("Name: %s, Age: %d, Height: %.2f\n", p->name, p->age, p->height);
}

LinkedNode* create_node(int value) {
    LinkedNode* node = (LinkedNode*)malloc(sizeof(LinkedNode));
    node->value = value;
    node->next = NULL;
    return node;
}

void append_node(LinkedNode* head, int value) {
    LinkedNode* current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = create_node(value);
}

int sum_list(LinkedNode* head) {
    int sum = 0;
    LinkedNode* current = head;
    while (current != NULL) {
        sum += current->value;
        current = current->next;
    }
    return sum;
}

void free_list(LinkedNode* head) {
    LinkedNode* current = head;
    while (current != NULL) {
        LinkedNode* next = current->next;
        free(current);
        current = next;
    }
}

int main(int argc, char** argv) {
    // Use Point
    Point p1 = make_point(10, 20);
    Point p2 = make_point(50, 80);
    printf("Points: (%d,%d) and (%d,%d)\n", p1.x, p1.y, p2.x, p2.y);

    // Use Rectangle
    Rectangle rect;
    rect.top_left = p1;
    rect.bottom_right = p2;
    printf("Rectangle area: %d\n", rectangle_area(&rect));

    // Use Person
    Person person;
    strcpy(person.name, "John Doe");
    person.age = 30;
    person.height = 5.9f;
    print_person(&person);

    // Use LinkedList
    LinkedNode* list = create_node(1);
    append_node(list, 2);
    append_node(list, 3);
    append_node(list, 4);
    printf("List sum: %d\n", sum_list(list));
    free_list(list);

    return 0;
}
