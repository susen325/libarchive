#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct archive *a = archive_read_new();
    if (a == NULL) {
        return 0;
    }

    archive_read_support_filter_all(a);
    archive_read_support_format_rar5(a);

    if (archive_read_open_memory(a, data, size) == ARCHIVE_OK) {
        struct archive_entry *entry;
        while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
            (void)archive_entry_pathname(entry);
            (void)archive_entry_pathname_utf8(entry);
            (void)archive_entry_pathname_w(entry);
            (void)archive_entry_symlink(entry);
            (void)archive_entry_symlink_utf8(entry);
            (void)archive_entry_symlink_w(entry);
            (void)archive_entry_hardlink(entry);
            (void)archive_entry_hardlink_utf8(entry);
            (void)archive_entry_hardlink_w(entry);
            (void)archive_entry_size(entry);
            (void)archive_entry_mtime(entry);
            (void)archive_entry_filetype(entry);
            (void)archive_entry_mode(entry);
            (void)archive_entry_uname(entry);
            (void)archive_entry_gname(entry);

            const void *buff;
            size_t bytes;
            int64_t offset;
            while (archive_read_data_block(a, &buff, &bytes, &offset) == ARCHIVE_OK) {
            }
        }
    }

    archive_read_free(a);
    return 0;
}