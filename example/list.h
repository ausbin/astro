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

typedef void (*list_free_func_t)(void *);
typedef void *(*list_copy_func_t)(void *);

extern list_t *list_new(void);
extern void list_free(list_t *list, list_free_func_t free_func);
extern list_t *list_deep_copy(list_t *list, list_copy_func_t copy_func,
                              list_free_func_t free_func);
extern int list_push(list_t *list, void *data);
extern int list_pop(list_t *list, void **data_out);

#endif
