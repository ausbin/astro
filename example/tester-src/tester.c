#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tester.h"

tester_t *tester_new(const char *elf_path) {
    tester_t *tester = calloc(1, sizeof (tester_t));
    if (!tester) {
        perror("calloc");
        abort();
    }
    tester->elf_path = elf_path;
    return tester;
}

void tester_free(tester_t *tester) {
    if (!tester)
        return;

    free(tester->tests);
    free(tester);
}

void _tester_push(tester_t *tester, test_t *test) {
    if (!tester || !test)
        return;

    // Need to grow this boy
    if (tester->tests_count == tester->tests_cap) {
        tester->tests_cap = tester->tests_cap * TESTER_TESTS_GROWTH_FACTOR + 1;
        tester->tests = realloc(tester->tests,
                                tester->tests_cap * sizeof (test_t));
        // Oopsie daisy, did I just leak? Damn right I did!
        if (!tester->tests) {
            perror("realloc");
            abort();
        }
    }

    memcpy(&tester->tests[tester->tests_count], test, sizeof (test_t));
    tester->tests_count++;
}

static int _tester_compare_heap_state(const void *left, const void *right) {
    const _tester_heap_state_t *left_block = left;
    const _tester_heap_state_t *right_block = right;

    return CMP(left_block->addr, right_block->addr);
}

// errmsg_size must be >= 3
bool _tester_assert_heap_state(astro_t *astro,
                               _tester_heap_state_t *heap_state_args,
                               size_t total_blocks, char *errmsg_out,
                               size_t errmsg_size) {
    qsort(heap_state_args, total_blocks, sizeof (_tester_heap_state_t),
          _tester_compare_heap_state);

    bool ok = true;
    astro_heap_iterator_t iter;
    astro_heap_iterate(astro, &iter);

    const astro_heap_block_t *block;
    while ((block = astro_heap_iterate_next(&iter))) {
        _tester_heap_state_t desired = { .addr = block->addr };
        _tester_heap_state_t *expected_block = bsearch(
                &desired, heap_state_args, total_blocks,
                sizeof (_tester_heap_state_t), _tester_compare_heap_state);

        if (!expected_block) {
            ok = false;

            int n;
            if ((n = snprintf(errmsg_out, errmsg_size,
                              "\t* address: 0x%lx, size: %lu bytes\n",
                              block->addr, block->size)) >= (int)errmsg_size) {
                for (int i = 0; i < 3; i++)
                    errmsg_out[errmsg_size - 1 - i] = '.';

                // Out of memory, so no point in continuining
                break;
            }

            errmsg_out += n + 1;
            errmsg_size -= n + 1;
        }
    }

    return ok;
}

test_t *tester_get_test(tester_t *tester, const char *test_name) {
    for (unsigned int i = 0; i < tester->tests_count; i++)
        if (!strcmp(test_name, tester->tests[i].name))
            return &tester->tests[i];

    return NULL;
}

const astro_err_t *tester_run_test(tester_t *tester, test_t *test, bool gdb) {
    astro_t *astro;
    const astro_err_t *astro_err;

    if ((astro_err = astro_new(tester->elf_path, &astro)))
        goto failure;

    if (!gdb || (astro_err = astro_host_gdb_server(astro)))
        goto failure;

    astro_err = test->func(test, astro);

    const astro_err_t *close_err;
    if (!gdb || (close_err = astro_close_gdb_server(astro)))
        astro_err = close_err;

    failure:
    // Need to duplicate, since the storage for an error is stored in
    // the astro_t struct itself
    astro_err = astro_errdup(astro_err);
    astro_free(astro);
    return astro_err;
}

const astro_err_t *tester_run_all_tests(tester_t *tester) {
    for (unsigned int i = 0; i < tester->tests_count; i++) {
        const astro_err_t *astro_err;
        if ((astro_err = tester_run_test(tester, &tester->tests[i], false)))
            return astro_err;
    }
    return NULL;
}
