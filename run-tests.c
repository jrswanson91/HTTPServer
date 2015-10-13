#include <glib.h>

void setup_test_hdrlist(void);
void setup_test_mimetypes(void);
void setup_test_request(void);

int main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_set_nonfatal_assertions();
    setup_test_hdrlist();
    setup_test_mimetypes();
    setup_test_request();
    return g_test_run();
}
