#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct archive *a = archive_read_new();
    if (a == NULL) return 0;
    archive_read_support_format_zip(a);
    archive_read_support_filter_all(a);
    if (archive_read_open_memory(a, data, size) == ARCHIVE_OK) {
        struct archive_entry *e;
        int n = 0;
        while (n++ < 4096 && archive_read_next_header(a, &e) == ARCHIVE_OK) {
            archive_entry_pathname(e);
            archive_entry_size(e);
            archive_entry_filetype(e);
            const void *buf; size_t len; int64_t off;
            while (archive_read_data_block(a, &buf, &len, &off) == ARCHIVE_OK) { }
        }
    }
    archive_read_free(a);
    return 0;
}
