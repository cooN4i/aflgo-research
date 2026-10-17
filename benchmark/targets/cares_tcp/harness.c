#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

static void callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
    if (res) {
        ares_freeaddrinfo(res);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 65536) {
        fclose(f);
        return 0;
    }

    unsigned char *buf = malloc(size + 1);
    if (!buf) {
        fclose(f);
        return 0;
    }

    size_t nread = fread(buf, 1, size, f);
    buf[nread] = '\0';
    fclose(f);

    ares_channel channel;
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.flags = ARES_FLAG_EDNS | ARES_FLAG_USEVC;
    opts.lookups = "b";

    if (ares_init_options(&channel, &opts, ARES_OPT_FLAGS | ARES_OPT_LOOKUPS) == ARES_SUCCESS) {
        struct ares_addrinfo_hints hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = ARES_AI_CANONNAME;

        ares_getaddrinfo(channel, (const char*)buf, NULL, &hints, callback, NULL);
        ares_destroy(channel);
    }

    free(buf);
    return 0;
}
