#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh2.h>
#include <libssh2_publickey.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 4 || size > 65536) {
        fclose(f);
        return 0;
    }

    unsigned char *buf = malloc(size);
    if (!buf) {
        fclose(f);
        return 0;
    }

    fread(buf, 1, size, f);
    fclose(f);

    libssh2_init(0);
    LIBSSH2_SESSION *session = libssh2_session_init();
    if (session) {
        // Feed packet buffer directly to publickey / transport packet handler
        LIBSSH2_PUBLICKEY *pk = libssh2_publickey_init(session);
        if (pk) {
            unsigned long num_attrs = 0;
            libssh2_publickey_list_fetch(pk, &num_attrs, NULL);
            libssh2_publickey_shutdown(pk);
        }
        libssh2_session_free(session);
    }
    libssh2_exit();

    free(buf);
    return 0;
}
