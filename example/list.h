#ifndef LIST_H
#define LIST_H

typedef struct list_node {
    void *data;
    struct list_node *next;
} list_node_t;

typedef struct {
    unsigned int size;
    list_node_t *head;
} list_t;

extern list_t *list_new(void);
extern void list_free(list_t *list);
extern list_t *list_deep_copy(list_t *list);

#endif
