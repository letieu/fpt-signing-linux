#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"

static int read_ef(sc_card_t *card, const char *path_str, u8 **out_buf, size_t *out_len) {
    sc_path_t path;
    sc_format_path(path_str, &path);
    sc_file_t *file = NULL;
    int r = sc_select_file(card, &path, &file);
    if (r != SC_SUCCESS) return r;

    size_t file_size = file->size;
    sc_file_free(file);

    u8 *buf = (u8 *)malloc(file_size + 32);
    if (!buf) return SC_ERROR_OUT_OF_MEMORY;

    r = sc_read_binary(card, 0, buf, file_size, 0);
    if (r < 0) {
        free(buf);
        return r;
    }

    *out_buf = buf;
    *out_len = (size_t)r;
    return SC_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <read-cert|read-key|verify-pin> [pin]\n", argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *pin = argc > 2 ? argv[2] : "";

    sc_context_t *ctx = NULL;
    sc_context_param_t ctx_param;
    memset(&ctx_param, 0, sizeof(ctx_param));
    ctx_param.app_name = "epass2003_tool";

    int r = sc_context_create(&ctx, &ctx_param);
    if (r != SC_SUCCESS) {
        fprintf(stderr, "Error creating context: %s\n", sc_strerror(r));
        return 10;
    }

    if (sc_ctx_get_reader_count(ctx) == 0) {
        fprintf(stderr, "No smartcard reader found.\n");
        sc_release_context(ctx);
        return 11;
    }

    sc_reader_t *reader = sc_ctx_get_reader(ctx, 0);
    sc_card_t *card = NULL;
    r = sc_connect_card(reader, &card);
    if (r != SC_SUCCESS) {
        fprintf(stderr, "No card or token found in reader: %s\n", sc_strerror(r));
        sc_release_context(ctx);
        return 12;
    }

    r = sc_lock(card);
    if (r != SC_SUCCESS) {
        fprintf(stderr, "Error locking card: %s\n", sc_strerror(r));
        sc_disconnect_card(card);
        sc_release_context(ctx);
        return 13;
    }

    // Select 3F00/2003
    sc_path_t path;
    sc_format_path("3F002003", &path);
    r = sc_select_file(card, &path, NULL);
    if (r != SC_SUCCESS) {
        fprintf(stderr, "Failed to select DF 2003: %s\n", sc_strerror(r));
        sc_unlock(card);
        sc_disconnect_card(card);
        sc_release_context(ctx);
        return 14;
    }

    if (strcmp(cmd, "read-cert") == 0) {
        u8 *cert_file = NULL;
        size_t cert_len = 0;
        r = read_ef(card, "3F00200324C0", &cert_file, &cert_len);
        if (r != SC_SUCCESS) {
            fprintf(stderr, "Failed to read 24C0: %s\n", sc_strerror(r));
            sc_unlock(card);
            sc_disconnect_card(card);
            sc_release_context(ctx);
            return 15;
        }

        // Find DER sequence (0x30 0x82)
        size_t der_start = 0;
        for (size_t i = 0; i + 4 < cert_len; i++) {
            if (cert_file[i] == 0x30 && cert_file[i+1] == 0x82) {
                der_start = i;
                break;
            }
        }

        size_t der_len = ((size_t)cert_file[der_start + 2] << 8) | cert_file[der_start + 3];
        der_len += 4;

        fwrite(cert_file + der_start, 1, der_len, stdout);
        free(cert_file);
        sc_unlock(card);
        sc_disconnect_card(card);
        sc_release_context(ctx);
        return 0;
    }

    // Verify PIN before accessing key
    if (strlen(pin) == 0) {
        fprintf(stderr, "PIN required.\n");
        sc_unlock(card);
        sc_disconnect_card(card);
        sc_release_context(ctx);
        return 20;
    }

    struct sc_pin_cmd_data pin_cmd;
    memset(&pin_cmd, 0, sizeof(pin_cmd));
    pin_cmd.cmd = SC_PIN_CMD_VERIFY;
    pin_cmd.pin_type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
    pin_cmd.pin_reference = 1;
    pin_cmd.pin1.data = (const u8 *)pin;
    pin_cmd.pin1.len = strlen(pin);

    r = sc_pin_cmd(card, &pin_cmd);
    if (r != SC_SUCCESS) {
        fprintf(stderr, "PIN verification failed: %s (retries left: %d)\n", sc_strerror(r), pin_cmd.pin1.tries_left);
        sc_unlock(card);
        sc_disconnect_card(card);
        sc_release_context(ctx);
        return 21;
    }

    if (strcmp(cmd, "verify-pin") == 0) {
        fprintf(stderr, "PIN verification successful!\n");
        sc_unlock(card);
        sc_disconnect_card(card);
        sc_release_context(ctx);
        return 0;
    }

    if (strcmp(cmd, "read-key") == 0) {
        u8 *key_file = NULL;
        size_t key_len = 0;
        r = read_ef(card, "3F00200324A0", &key_file, &key_len);
        if (r != SC_SUCCESS) {
            fprintf(stderr, "Failed to read 24A0: %s\n", sc_strerror(r));
            sc_unlock(card);
            sc_disconnect_card(card);
            sc_release_context(ctx);
            return 22;
        }

        fwrite(key_file, 1, key_len, stdout);
        free(key_file);
        sc_unlock(card);
        sc_disconnect_card(card);
        sc_release_context(ctx);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    sc_unlock(card);
    sc_disconnect_card(card);
    sc_release_context(ctx);
    return 1;
}
