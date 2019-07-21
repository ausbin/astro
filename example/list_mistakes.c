#include <stdlib.h>
#include "list.h"

// These are mistakes students make

//// list_new() mistakes ////

list_t *list_new__null(void) {
    return NULL;
}

list_t *list_new__freed(void) {
    list_t *list = calloc(1, sizeof (list_t));
    free(list);
    return list;
}

list_t *list_new__doubly_freed(void) {
    list_t *list = calloc(1, sizeof (list_t));
    free(list);
    free(list);
    return list;
}

list_t *list_new__uninit(void) {
    return malloc(sizeof (list_t));
}

list_t *list_new__stack(void) {
    list_t list = { .size = 0, .head = NULL };
    list_t *list_p = &list;
    return list_p;
}

list_t *list_new__readonly_static(void) {
    return (list_t *) "where are my pancakes thomas";
}

list_t *list_new__writable_static(void) {
    static list_t list = { .size = 0, .head = NULL };
    return &list;
}

list_t *list_new__stray_heap(void) {
    return (list_t *) ((char *) calloc(1, sizeof (list_t) + 1) + 1);
}

list_t *list_new__undersized(void) {
    return calloc(1, 1);
}

list_t *list_new__oversized(void) {
    return calloc(1, sizeof (list_t) + 1);
}

list_t *list_new__leak(void) {
    malloc(69);
    return calloc(1, sizeof (list_t));
}

list_t *list_new__bad_free(void) {
    free((void *) 0x69);
    return calloc(1, sizeof (list_t));
}

list_t *list_new__infiniloop(void) {
    while (1);
    return calloc(1, sizeof (list_t));
}

list_t *list_new__null_segfault(void) {
    return *(list_t **)NULL;
}

list_t *list_new__genius_segfault(void) {
    return *(list_t **)0x69;
}

list_t *list_new__oom_segfault(void) {
    list_t *list = malloc(sizeof (list_t));
    list->size = 0;
    list->head = NULL;
    return list;
}

//// list_push() mistakes ////

int list_push__free_list(list_t *list, void *data) {
    (void)data;
    free(list);
    return 1;
}

int list_push__free_data(list_t *list, void *data) {
    (void)list;
    free(data);
    return 1;
}
