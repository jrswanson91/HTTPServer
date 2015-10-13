#ifndef HTTPD_REQUEST_H
#define HTTPD_REQUEST_H

#include <sys/types.h>
#include <stdbool.h>

#include "httpdefs.h"

typedef struct http_request req_t;

/**
 * Create a new request.
 */
req_t* req_create(void);
/**
 * Destroy a request, freeing its allocated resources.
 */
void req_destroy(req_t* req);

/**
 * Query whether a request has completed.
 */
bool req_is_complete(req_t* req);
/**
 * Query whether a request is valid.  If the request is complete but not valid,
 * then it is malformed and the server should probably send a 400.
 */
bool req_is_valid(req_t* req);
/**
 * Query whether a request is simple (HTTP 0.9).
 */
bool req_is_simple(req_t* req);

/**
 * Get the protocol version for a request.
 */
http_version_t req_http_version(req_t* req);

/**
 * Feed bytes into the request parser.
 * @param data The data to parse.
 * @param len The length of the data buffer
 * @return The number of bytes consumed from data, or the -1 if there is an error.
 */
ssize_t req_parse(req_t *req, const char *data, size_t len);

/**
 * Get the HTTP method for a request.
 * @param req The request
 * @return The HTTP method.
 */
http_method_t req_method(req_t* req);

/**
 * Get the raw path for a request.
 * @param req The request.
 * @return The path, or NULL if the request is incomplete.  The path is returned without
 * processing for query strings or URI escapes.  This value <strong>must not</strong> be
 * freed, as it is owned by the request.
 */
const char* req_raw_path(req_t* req);

/**
 * Get the path for a request.
 * @param req The request.
 * @return The path, or NULL if the request is incomplete.  The returned path contains
 * only the path portion of the URI, and is decoded (URI escape characters handled) and
 * ready to use.
 */
const char* req_path(req_t* req);

/**
 * Get the value of a request header.
 * @param req The request.
 * @param name The name of the header.
 * @return The header's value, or NULL if no such header is present.  This
 * value <strong>must not</strong> be freed, as it is owned by the request.
 */
const char* req_header(req_t* req, const char *name);

/**
 * Get the address of the host, suitable for building redirects.
 */
const char* req_host(req_t* req);

/**
 * Get the content length for a request.
 * @param req The request.
 * @return The value of the Content-Length header.  Returns 0 if the request is complete
 * but there is no Content-Length, and -1 if the request is incomplete (or has an invalid
 * content-length).
 */
ssize_t req_content_length(req_t* req);

#endif // !defined(HTTPD_REQUEST_H)
