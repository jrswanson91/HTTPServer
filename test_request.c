#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "request.h"

static void rq_setup(req_t **fix, const void *data)
{
    *fix = req_create();
}

static void rq_teardown(req_t **fix, const void *data)
{
    req_destroy(*fix);
}

static ssize_t feed_string(req_t *req, const char *str)
{
    return req_parse(req, str, strlen(str));
}

//#test_fixture req_t*
//#test_setup rq_setup
//#test_teardown rq_teardown
//#test_prefix /request

static void test_create_destroy(req_t **fix, const void *data)
{
    req_t *req = *fix;
    g_assert_nonnull(req);
    g_assert(!req_is_complete(req));
    g_assert(!req_is_valid(req));
    g_assert(!req_is_simple(req));
    g_assert_cmpint(req_method(req), ==, -1);
    g_assert_cmpstr(req_raw_path(req), ==, NULL);
    g_assert_cmpstr(req_header(req, "accept"), ==, NULL);
    g_assert_cmpint(req_content_length(req), <, 0);
}

static void test_parse_simple(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello\r\n");
    g_assert_cmpint(n, ==, 12);
    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert(req_is_complete(request));
    g_assert(req_is_valid(request));
    g_assert(req_is_simple(request));
    g_assert_cmpint(req_http_version(request), ==, HTTP_VERSION_09);
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
    g_assert_cmpint(req_content_length(request), ==, 0);
}

static void test_fail_on_null(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = req_parse(request, "GET /\0hello\r\n", 13);
    g_assert_cmpint(n, <, 0);
    g_assert(req_is_complete(request));
    g_assert(!req_is_valid(request));
}

static void test_parse_simple_split(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET ");
    g_assert_cmpint(n, ==, 4);
    n = feed_string(request, "/hello\r\n");
    g_assert_cmpint(n, ==, 8);
    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert(req_is_complete(request));
    g_assert(req_is_valid(request));
    g_assert(req_is_simple(request));
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
}

static void test_parse_simple_lf(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello\n");
    g_assert_cmpint(n, ==, 11);
    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert(req_is_complete(request));
    g_assert(req_is_valid(request));
    g_assert(req_is_simple(request));
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
}

static void test_parse_simple_done(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello\r\n\r\n");
    g_assert_cmpint(n, ==, 12);
    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert(req_is_complete(request));
    g_assert(req_is_valid(request));
    g_assert(req_is_simple(request));
    g_assert_cmpint(req_http_version(request), ==, HTTP_VERSION_09);
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
}

static void test_parse_request_line(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello HTTP/1.0\r\n");
    g_assert_cmpint(n, ==, 21);
    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert_cmpint(req_http_version(request), ==, HTTP_VERSION_10);
    g_assert(!req_is_complete(request));
    g_assert(!req_is_simple(request));
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
}

static void test_parse_request_no_headers(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello HTTP/1.0\r\n\r\n");
    g_assert_cmpint(n, ==, 23);
    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert(req_is_complete(request));
    g_assert_cmpint(req_http_version(request), ==, HTTP_VERSION_10);
    g_assert(!req_is_simple(request));
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
}

static void test_parse_request_no_headers_leftover(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello HTTP/1.0\r\n\r\n\r\n");
    g_assert_cmpint(n, ==, 23);
    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert(req_is_complete(request));
    g_assert_cmpint(req_http_version(request), ==, HTTP_VERSION_10);
    g_assert(!req_is_simple(request));
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
}

static void test_parse_invald_line(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "foobar\n");
    g_assert_cmpint(n, <, 0);
    g_assert(req_is_complete(request));
    g_assert(!req_is_valid(request));
}

static void test_request_header(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello HTTP/1.0\r\n");
    g_assert_cmpint(n, ==, 21);
    n = feed_string(request, "Accept: text/html\r\n");
    g_assert_cmpint(n, ==, 19);
    n = feed_string(request, "Content-Length: 0\r\n");
    g_assert_cmpint(n, ==, 19);
    n = feed_string(request, "\r\n");
    g_assert_cmpint(n, ==, 2);

    g_assert_cmpint(req_method(request), ==, HTTP_METHOD_GET);
    g_assert(req_is_complete(request));
    g_assert_cmpint(req_http_version(request), ==, HTTP_VERSION_10);
    g_assert(!req_is_simple(request));
    g_assert_cmpstr(req_raw_path(request), ==, "/hello");
    g_assert_cmpstr(req_header(request, "accept"), ==, "text/html");
    g_assert_cmpstr(req_header(request, "content-length"), ==, "0");
    g_assert_null(req_header(request, "content-type"));
    g_assert_cmpint(req_content_length(request), ==, 0);
}

static void test_content_length(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello HTTP/1.0\r\n");
    g_assert_cmpint(n, ==, 21);
    n = feed_string(request, "Accept: text/html\r\n");
    g_assert_cmpint(n, ==, 19);
    n = feed_string(request, "Content-Length: 128\r\n");
    g_assert_cmpint(n, ==, 21);
    n = feed_string(request, "\r\n");
    g_assert_cmpint(n, ==, 2);

    g_assert_cmpint(req_content_length(request), ==, 128);
}

static void test_host(req_t **fix, const void *data)
{
    req_t *request = *fix;
    ssize_t n = feed_string(request, "GET /hello HTTP/1.0\r\n");
    g_assert_cmpint(n, ==, 21);
    n = feed_string(request, "Host: localhost:4080\r\n");
    g_assert_cmpint(n, ==, 22);
    n = feed_string(request, "\r\n");
    g_assert_cmpint(n, ==, 2);
    g_assert(req_is_complete(request));

    g_assert_cmpstr(req_host(request), ==, "localhost:4080");
}

static void test_basic_path(req_t **fix, const void *data)
{
    req_t *req = *fix;
    feed_string(req, "GET /hello HTTP/1.0\r\n\r\n");
    g_assert(req_is_complete(req));
    g_assert(req_is_valid(req));
    g_assert_cmpstr(req_raw_path(req), ==, "/hello");
    g_assert_cmpstr(req_path(req), ==, "/hello");
}

static void test_escape_path(req_t **fix, const void *data)
{
    req_t *req = *fix;
    feed_string(req, "GET /hello%20world HTTP/1.0\r\n\r\n");
    g_assert(req_is_complete(req));
    g_assert(req_is_valid(req));
    g_assert_cmpstr(req_raw_path(req), ==, "/hello%20world");
    g_assert_cmpstr(req_path(req), ==, "/hello world");
}

static void test_path_with_query(req_t **fix, const void *data)
{
    req_t *req = *fix;
    feed_string(req, "GET /hello?who=world HTTP/1.0\r\n\r\n");
    g_assert(req_is_complete(req));
    g_assert(req_is_valid(req));
    g_assert_cmpstr(req_raw_path(req), ==, "/hello?who=world");
    g_assert_cmpstr(req_path(req), ==, "/hello");
}

static void test_escaped_path_with_query(req_t **fix, const void *data)
{
    req_t *req = *fix;
    feed_string(req, "GET /hello%20world?why=morning HTTP/1.0\r\n\r\n");
    g_assert(req_is_complete(req));
    g_assert(req_is_valid(req));
    g_assert_cmpstr(req_raw_path(req), ==, "/hello%20world?why=morning");
    g_assert_cmpstr(req_path(req), ==, "/hello world");
}

void setup_test_request()
{
#include "test_request.ch"
}
