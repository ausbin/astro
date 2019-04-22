#include <stdio.h>
#include "list.h"

list_t *list_new(void) {
    return NULL;
}

void list_free(list_t *list) {
    (void)list;
}

int list_deep_copy(list_t *list, list_t **new_list_out) {
    (void)list;
    (void)new_list_out;
    return 0;
}
