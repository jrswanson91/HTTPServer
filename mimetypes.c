#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include "mimetypes.h"

struct type_entry {
    const char *ext;
    const char *type;
};

#include "mime_type_table.ch"

const char* guess_content_type(const char *file)
{
    const char *ext;
    const struct type_entry *te;

    g_return_val_if_fail(file != NULL, NULL);

    ext = strrchr(file, '.');
    if (!ext) {
        return NULL;
    }

    // advance past '.'
    ext++;
    for (te = mime_type_table; te->ext; te++) {
        if (strcasecmp(ext, te->ext) == 0) {
            return te->type;
        }
    }

    return NULL;
}
