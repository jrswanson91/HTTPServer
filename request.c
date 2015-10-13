#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <glib.h>

#include "hdrlist.h"
#include "httpdefs.h"
#include "request.h"
#include "debug.h"

typedef enum parse_state {
    STATE_INITIAL,
    STATE_IN_HEADER,
    STATE_COMPLETE,
    STATE_INVALID
} parse_state_t;

struct http_request {
    parse_state_t state;
    http_method_t method;
    http_version_t http_version;
    hdrlist_t *headers;
    char *uri;
    char *buf;
    char *path;
    size_t buf_size;
    bool line_ready;
};

req_t* req_create(void)
{
    // allocate memory
    req_t* req = g_malloc(sizeof(struct http_request));

    // initialize variables
    req->state = STATE_INITIAL;
    req->http_version = 0;
    req->method = -1;
    req->path = NULL;
    req->uri = NULL;
    req->buf = NULL;
    req->buf_size = 0;
    req->line_ready = false;
    req->headers = hl_create();

    return req;
}

void req_destroy(req_t* req)
{
    g_return_if_fail(req != NULL);

    g_free(req->path);
    g_free(req->uri);
    g_free(req->buf);
    hl_destroy(req->headers);
    g_free(req);
}

bool req_is_complete(req_t* req)
{
    g_return_val_if_fail(req != NULL, false);
    return req->state >= STATE_COMPLETE;
}

bool req_is_valid(req_t* req)
{
    g_return_val_if_fail(req != NULL, false);
    return req->state >= STATE_COMPLETE && req->state < STATE_INVALID;
}

bool req_is_simple(req_t* req)
{
    g_return_val_if_fail(req != NULL, false);
    return req->http_version == HTTP_VERSION_09;
}

http_version_t req_http_version(req_t* req)
{
    g_return_val_if_fail(req != NULL, 0);
    return req->http_version;
}

http_method_t req_method(req_t* req)
{
    g_return_val_if_fail(req != NULL, -1);
    return req->method;
}

const char* req_raw_path(req_t* req)
{
    g_return_val_if_fail(req != NULL, NULL);
    return req->uri;
}

const char* req_path(req_t* req)
{
    g_return_val_if_fail(req != NULL, NULL);
    if (!req->uri) {
        return NULL;
    }

    if (!req->path) {
        char *end = strchr(req->uri, '?');
        req->path = g_uri_unescape_segment(req->uri, end, NULL);
    }

    return req->path;
}

const char* req_header(req_t* req, const char *name)
{
    g_return_val_if_fail(req != NULL, NULL);
    return hl_find(req->headers, name);
}

const char* req_host(req_t* req)
{
    g_return_val_if_fail(req != NULL, NULL);
    g_return_val_if_fail(req_is_complete(req), NULL);

    return req_header(req, "host");
}

ssize_t req_content_length(req_t* req)
{
    g_return_val_if_fail(req != NULL, -1);

    if (!req_is_complete(req)) {
        return -1;
    }

    const char *clhdr = req_header(req, "content-length");
    if (clhdr == NULL) {
        return 0;
    } else {
        ssize_t len = g_ascii_strtoll(clhdr, NULL, 10);
        if (len == 0 && errno == EINVAL) {
            g_warning("invalid content length %s", clhdr);
            return -1;
        }
        return len;
    }
}

static int parse_request_line(req_t *req, const char *data, size_t len)
{
    // Copy the data for internal modification
    char *copy = g_strndup(data, len);

    // Look for space
    char *path = strchr(copy, ' ');
    if (!path) {
        // the request line is invalid
        req->state = STATE_INVALID;
        g_free(copy);
        return -1;
    }
    // Before the space is the method, after the path
    *path = 0;
    path++;

    if (!strcmp(copy, "GET")) {
        req->method = HTTP_METHOD_GET;
    } else if (!strcmp(copy, "HEAD")) {
        req->method = HTTP_METHOD_HEAD;
    } else if (!strcmp(copy, "POST")) {
        req->method = HTTP_METHOD_POST;
    } else {
        req->state = STATE_INVALID;
        g_free(copy);
        return -1;
    }

    // look for end of path
    char *ver = strchr(path, ' ');
    if (ver) {
        *ver = 0;
        ver++;
        req->uri = g_strdup(path);
        if (strcmp(ver, "HTTP/1.0") == 0) {
            req->http_version = HTTP_VERSION_10;
            req->state = STATE_IN_HEADER;
        } else if (strcmp(ver, "HTTP/1.1") == 0) {
            req->http_version = HTTP_VERSION_11;
            req->state = STATE_IN_HEADER;
        } else {
            req->state = STATE_INVALID;
            g_free(copy);
            return -1;
        }
    } else {
        // simple request
        // do another strdup so that we can sanely free
        req->uri = g_strdup(path);
        req->state = STATE_COMPLETE;
        req->http_version = HTTP_VERSION_09;
    }

    g_free(copy);
    return 0;
}

static int parse_header_line(req_t *req, const char *data, size_t len)
{
    const char *sep = strchr(data, ':');
    
    if (!sep) {
        req->state = STATE_INVALID;
        return -1;
    }

    char *name = g_strndup(data, sep - data);
    const char *value = sep + 1;
    // advance value through blanks
    while (*value && isblank(*value)) {
        value++;
    }
    // now we have the header value
    hl_add(req->headers, name, value);

    // done with tmp name
    g_free(name);
    
    return 0;
}

static ssize_t req_feed_line(req_t *req, const char *data, size_t len)
{
    char *eol = strchr(data, '\n');
    size_t used = 0;
    if (eol) {
        used = eol - data + 1;
        if (eol > data && *(eol-1) == '\r') {
            eol--;
        }
        size_t line_len = eol - data;

        if (req->buf) {
            char *nbuf = g_realloc(req->buf, req->buf_size + line_len + 1);
            req->buf = nbuf;
        } else {
            assert(req->buf_size == 0);
            req->buf = g_malloc(line_len + 1);
        }
        memcpy(req->buf + req->buf_size, data, line_len);
        req->buf_size += line_len;
        req->buf[req->buf_size] = 0;
        req->line_ready = true;
    } else {
        if (req->buf) {
            char *nbuf = g_realloc(req->buf, req->buf_size + len + 1);
            req->buf = nbuf;
        } else {
            assert(req->buf_size == 0);
            req->buf = g_malloc(len + 1);
        }
        memcpy(req->buf + req->buf_size, data, len);
        req->buf_size += len;
        req->buf[req->buf_size] = 0;
        used = len;
    }
    return used;
}

ssize_t req_parse(req_t *req, const char *data, size_t len)
{
    g_return_val_if_fail(req != NULL, -1);
    g_return_val_if_fail(data != NULL, -1);
    if (req_is_complete(req)) {
        g_warning("request already complete");
        return 0;
    }

    if (strlen(data) < len) {
        // we have a null somewhere in the string
        req->state = STATE_INVALID;
        return -1;
    }

    /* request not complete, data looks good.
     * time to split and parse. */

    ssize_t pos = 0;
    while (pos < len && !req_is_complete(req)) {
        ssize_t line_len;
        line_len = req_feed_line(req, data + pos, len - pos);
        if (line_len < 0) {
            // TODO better errors
            return -1;
        }
        pos += line_len;

        if (req->line_ready) {
            switch (req->state) {
                case STATE_INITIAL:
                    if (parse_request_line(req, req->buf, req->buf_size) < 0) {
                        return -1;
                    }
                    break;
                case STATE_IN_HEADER:
                    if (req->buf_size == 0) {
                        req->state = STATE_COMPLETE;
                    } else if (parse_header_line(req, req->buf, req->buf_size) < 0) {
                        return -1;
                    }
                    break;
                case STATE_COMPLETE:
                case STATE_INVALID:
                    g_return_val_if_reached(-1);
                    break;
            }
            g_free(req->buf);
            req->buf = NULL;
            req->buf_size = 0;
            req->line_ready = false;
        }
    }

    return pos;
}
