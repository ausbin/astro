#include <stdlib.h>
#include "list.h"

list_t *list_new_good(void) {
    return calloc(1, sizeof (list_t));
}

void list_free(list_t *list) {
    (void)list;
}

list_t *list_deep_copy(list_t *list) {
    (void)list;
    return NULL;
}
