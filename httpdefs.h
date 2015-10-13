#ifndef HTTPD_DEFS_H
#define HTTPD_DEFS_H

typedef enum http_version {
    HTTP_VERSION_09 = 9,
    HTTP_VERSION_10,
    HTTP_VERSION_11
} http_version_t;
typedef enum http_method {
    HTTP_METHOD_UNKNOWN = -1,
    HTTP_METHOD_GET = 0,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST
} http_method_t;

#endif // !defined(HTTPD_DEFS_H)
