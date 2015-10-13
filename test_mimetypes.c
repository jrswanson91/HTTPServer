#include <stdlib.h>
#include <glib.h>

#include "mimetypes.h"

//#test_prefix /mimetypes

static void test_foobar_null()
{
    const char *type = guess_content_type("foo.wombat");
    g_assert_null(type);
}

static void test_html()
{
    const char *type = guess_content_type("index.html");
    g_assert_cmpstr(type, ==, "text/html");
}

static void test_htm()
{
    const char *type = guess_content_type("index.htm");
    g_assert_cmpstr(type, ==, "text/html");
}

static void test_html_upcase()
{
    const char *type = guess_content_type("INDEX.HTML");
    g_assert_cmpstr(type, ==, "text/html");
}

static void test_double_extension()
{
    const char *type = guess_content_type("index.html.jpg");
    g_assert_cmpstr(type, ==, "image/jpeg");
}

void setup_test_mimetypes()
{
#include "test_mimetypes.ch"
}
