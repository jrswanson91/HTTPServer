#ifndef HTTP_HDRLIST_H
#define HTTP_HDRLIST_H

typedef struct header {
    char *name;
    char *value;
} header_t;

typedef struct header_list hdrlist_t;

hdrlist_t* hl_create(void);
void hl_destroy(hdrlist_t *hl);

size_t hl_size(hdrlist_t *hl);
void hl_add(hdrlist_t *hl, const char *name, const char *value);
void hl_remove(hdrlist_t *hl, const char *name);
const char* hl_find(hdrlist_t *hl, const char *name);

/**
 * Convert a hdrlist to a GList of pointers to header structures.
 * The caller must free the list with g_list_free, but must not free
 * the headers it points to.
 */
GList* hl_to_list(hdrlist_t *hl);

#endif // !defined(HTTP_HDRLIST_H)
