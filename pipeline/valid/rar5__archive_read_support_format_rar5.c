#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct archive *a = archive_read_new();
    if (a == NULL) {
        return 0;
    }

    archive_read_support_format_rar5(a);
    archive_read_support_filter_all(a);

    if (archive_read_open_memory(a, data, size) == ARCHIVE_OK) {
        struct archive_entry *e;
        while (archive_read_next_header(a, &e) == ARCHIVE_OK) {
            (void)archive_entry_pathname(e);
            (void)archive_entry_pathname_w(e);
            (void)archive_entry_symlink(e);
            (void)archive_entry_hardlink(e);
            (void)archive_entry_size(e);
            (void)archive_entry_mtime(e);
            (void)archive_entry_ctime(e);
            (void)archive_entry_atime(e);
            (void)archive_entry_mode(e);
            (void)archive_entry_filetype(e);
            (void)archive_entry_is_encrypted(e);

            const void *buff;
            size_t bytes;
            int64_t offset;
            while (archive_read_data_block(a, &buff, &bytes, &offset) == ARCHIVE_OK) {
            }
        }
        archive_read_has_encrypted_entries(a);
        archive_read_format_capabilities(a);
        archive_read_close(a);
    }

    archive_read_free(a);
    return 0;
}