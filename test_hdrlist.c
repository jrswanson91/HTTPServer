#include <stdlib.h>
#include <glib.h>

#include "hdrlist.h"

struct fixture {
    hdrlist_t *hl;
};

static void hl_setup(struct fixture *fix, const void *data)
{
    fix->hl = hl_create();
}

static void hl_teardown(struct fixture *fix, const void *data)
{
    hl_destroy(fix->hl);
}

//#test_fixture struct fixture
//#test_setup hl_setup
//#test_teardown hl_teardown
//#test_prefix /hdrlist

static void test_create_destroy(struct fixture *fix, const void *data)
{
    hdrlist_t *hl = fix->hl;
    g_assert_nonnull(hl);
    g_assert_cmpint(hl_size(hl), ==, 0);
    g_assert_null(hl_find(hl, "content-type"));
    g_assert_null(hl_to_list(hl));
}

static void test_add_one(struct fixture *fix, const void *data)
{
    hdrlist_t *hl = fix->hl;
    hl_add(hl, "Content-Type", "text/html");
    g_assert_cmpint(hl_size(hl), ==, 1);
    g_assert_cmpstr(hl_find(hl, "Content-Type"), ==, "text/html");
    g_assert_cmpstr(hl_find(hl, "content-type"), ==, "text/html");
    g_assert_null(hl_find(hl, "accept"));
    GList* headers = hl_to_list(hl);
    g_assert_nonnull(headers);
    g_assert_cmpint(g_list_length(headers), ==, 1);
    g_assert_cmpstr(((header_t*) headers->data)->name, ==, "Content-Type");
    g_assert_cmpstr(((header_t*) headers->data)->value, ==, "text/html");
    g_list_free(headers);

    /* search again, make sure free didn't break internals */
    g_assert_cmpstr(hl_find(hl, "content-type"), ==, "text/html");
}

static void test_add_replace(struct fixture *fix, const void *data)
{
    hdrlist_t *hl = fix->hl;
    hl_add(hl, "Content-Type", "text/html");
    hl_add(hl, "Content-Type", "text/plain");
    g_assert_cmpint(hl_size(hl), ==, 1);
    g_assert_cmpstr(hl_find(hl, "Content-Type"), ==, "text/plain");
}

static void test_add_replace_case(struct fixture *fix, const void *data)
{
    hdrlist_t *hl = fix->hl;
    hl_add(hl, "Content-Type", "text/html");
    hl_add(hl, "content-type", "text/plain");
    g_assert_cmpint(hl_size(hl), ==, 1);
    g_assert_cmpstr(hl_find(hl, "Content-Type"), ==, "text/plain");
}

static void test_add_two(struct fixture *fix, const void *data)
{
    hdrlist_t *hl = fix->hl;
    hl_add(hl, "Content-Type", "text/html");
    hl_add(hl, "Content-Length", "42");
    g_assert_cmpint(hl_size(hl), ==, 2);
    g_assert_cmpstr(hl_find(hl, "Content-Type"), ==, "text/html");
    g_assert_cmpstr(hl_find(hl, "content-length"), ==, "42");
    g_assert_null(hl_find(hl, "accept"));
    GList* headers = hl_to_list(hl);
    g_assert_nonnull(headers);
    g_assert_cmpint(g_list_length(headers), ==, 2);
    g_assert_cmpstr(((header_t*) headers->data)->name, ==, "Content-Type");
    g_assert_cmpstr(((header_t*) headers->data)->value, ==, "text/html");
    g_assert_cmpstr(((header_t*) headers->next->data)->name, ==, "Content-Length");
    g_list_free(headers);
}

void setup_test_hdrlist()
{
#include "test_hdrlist.ch"
}
