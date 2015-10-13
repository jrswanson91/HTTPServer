#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <glib.h>

#include "hdrlist.h"
#include "debug.h"

struct header_list {
    header_t *headers;
    size_t size;
    size_t capacity;
};

hdrlist_t* hl_create(void)
{
    hdrlist_t *nhl = g_new(hdrlist_t, 1);

    nhl->size = 0;
    nhl->capacity = 10;
    // this is OK on most platforms
    // a few weird platforms would require a different nulling strategy
    nhl->headers = g_new0(header_t, 10);

    return nhl;
}

void hl_destroy(hdrlist_t *hl)
{
    int i;
    g_return_if_fail(hl != NULL);
    for (i = 0; i < hl->size; i++) {
        g_free(hl->headers[i].name);
        g_free(hl->headers[i].value);
    }
    g_free(hl->headers);
    g_free(hl);
}

size_t hl_size(hdrlist_t *hl)
{
    return hl->size;
}

void hl_add(hdrlist_t *hl, const char *name, const char *value)
{
    int j;
    off_t pos;

    g_return_if_fail(hl != NULL);
    
    for (pos = 0; pos < hl->size; pos++) {
        if (strcasecmp(name, hl->headers[pos].name) == 0) {
            break;
        }
    }

    if (pos < hl->size) {
        char *dup = g_strdup(value);
        g_free(hl->headers[pos].value);
        hl->headers[pos].value = dup;
    } else {
        g_assert(pos == hl->size);
        if (pos == hl->capacity) {
            size_t ncap = hl->capacity * 2;
            hl->headers = g_realloc_n(hl->headers, ncap, sizeof(header_t));
            for (j = hl->size; j < ncap; j++) {
                hl->headers[j].name = NULL;
                hl->headers[j].value = NULL;
            }
            hl->capacity = ncap;
        }
        hl->headers[pos].name = g_strdup(name);
        hl->headers[pos].value = g_strdup(value);
        hl->size += 1;
    }
}

void hl_remove(hdrlist_t *hl, const char *name)
{
}

const char* hl_find(hdrlist_t *hl, const char *name)
{
    int i;

    g_return_val_if_fail(hl != NULL, NULL);

    for (i = 0; i < hl->size; i++) {
        if (g_ascii_strcasecmp(hl->headers[i].name, name) == 0) {
            return hl->headers[i].value;
        }
    }

    return NULL;
}

GList* hl_to_list(hdrlist_t *hl)
{
    g_return_val_if_fail(hl != NULL, NULL);
    int i;
    GList* list = NULL;
    for (i = hl->size - 1; i >= 0; i--) {
        list = g_list_prepend(list, &(hl->headers[i]));
    }
    return list;
}
