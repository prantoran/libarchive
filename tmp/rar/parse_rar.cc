/*
Objectives:
Parse CMT service header (if exist) for RAR5 format
- Header type for service header is 0x03
- CMT contents are in the data area

data size field, present if header flag has 0x02

Cannot handle sfx directly, need to extract .rar from overlay first.

CMT will be part of the service header, which will be followed by data area containing CMT's content.
*/

#include <cstdio>
#include <archive.h>
#include <archive_entry.h>
#include <stdlib.h>
#include <string.h>

#include "rar3.h"
#include "rar5.h"
#include "../utils.h"

static int callback_call_cnt = 0;
static uint8_t buf[MAX_HEADER_SIZE_RAR5 + 5]; // Buffer for reading data

static char archive_name[1024];
static char config_filename[1024];

uint8_t rar_type_found = 0;

void print_bytes(uint8_t * b1, uint8_t * b2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dprint(stderr, "b1[%zu]: 0x%02x  b2[%zu]: 0x%02x\n", i, b1[i], i, b2[i]);
    }
}

int	my_open_callback(struct archive *, void *client_data) {
    dprint(stderr, "my_open_callback() called\n");
    FILE *file = (FILE *)client_data;
    if (!file) {
        dprint(stderr, "my_open_callback(): Null file pointer\n");
        return ARCHIVE_WARN;
    }
    // get archive/file size
    fseek(file, 0, SEEK_END);
    size_t sz = ftell(file);
    rewind(file);
    dprint(stderr, "File size: %ld bytes\n", sz); // must match `ll -h ***.rar`
    size_t bytes_read = 0;
    bytes_read = fread(buf, 1, sz < MAX_HEADER_SIZE_RAR5? sz: MAX_HEADER_SIZE_RAR5, file);
    dprint(stderr, "bytes_read for buf: %d\n", bytes_read);
    rewind(file);

    for (int i = 0; i < 16; i ++) {
        dprint(stderr, "0x%02x ", *(buf + i));
    } dprint(stderr, "\n");
    dprint(stderr, "\n");
    get_filename_no_ext(archive_name, config_filename, strlen(archive_name));
    strcat(config_filename, "_config.txt");
    void * cmt_buffer = NULL;
    size_t cmt_buffer_size;
    if (rar5::is_valid_signature(buf)) {
        rar_type_found = (1<<5);
        fprintf(stdout, "RAR5 signature found\n");
        rar5::parse_cmt(&cmt_buffer, &cmt_buffer_size, (uint8_t *)buf, sz);
    } else if (rar4::is_valid_signature(buf)) {
        rar_type_found = (1<<4);
        fprintf(stdout, "RAR4 signature found\n");
        rar4::parse_cmt(&cmt_buffer, &cmt_buffer_size, (uint8_t *)buf, sz);    
    } else if (buf[0] == 0x4d && buf[1] == 0x5a) {
        fprintf(stdout, "PE signature found, probably SFX\n");
    } else {
        fprintf(stderr, "[WARN] No RAR or PE signature not found at start of buffer\n");
        return ARCHIVE_WARN;
    }
    if (cmt_buffer) {
        dprint(stderr, "Creating %s.\n", config_filename);
        write_to_file(config_filename, cmt_buffer, cmt_buffer_size);
        free(cmt_buffer);
    }
    return ARCHIVE_OK; // must return 0 if no error, since checked in libarchive/archive_read.c::archive_read_open1()
}

int	my_close_callback(struct archive *, void *_client_data) {
    dprint(stderr, "my_close_callback() called\n");
}

// Custom read callback 01011110000010
// First time the callback is called on the .rar file itself, apparent from the signature.
// Callback can be called multiple times for the same file, each time reading a chunk of data.
// Callbacks irrespective of whether archive_read_data, archive_write_header, etc are called.
// client_data is pointer to file, not the actual content.
ssize_t my_read_callback(struct archive *a, void *client_data, const void **buffer) {
    callback_call_cnt ++;
    dprint(stderr, "my_read_callback() call count: %d\n", callback_call_cnt);
    FILE *file = (FILE *)client_data;
    size_t bytes_read = 0;
    bytes_read = fread(buf, 1, sizeof(buf), file);

    // dprint(stderr, "bytes_read: %d\n", bytes_read);
    // for (int i = 0;i < bytes_read && i < 100; i++) {
    //     dprint(stderr, "%02x ", (unsigned char)buf[i]);
    // } dprint(stderr, "\n");

    if (rar_type_found & (1<<5)) {
        rar5::parse_rar5_general_headers(buf);
    }

    if (bytes_read > 0) {
        *buffer = buf; // Point to the data read
        return bytes_read; // Return the number of bytes read
    }
    return feof(file) ? 0 : -1; // Return 0 for EOF, -1 for error
}

void process_xattrs(struct archive_entry *entry) {
    const char *name;
    const void *value;
    size_t size;

    // Iterate through all extended attributes
    while (archive_entry_xattr_next(entry, &name, &value, &size) == ARCHIVE_OK) {
        dprint(stderr, "Xattr> %s: %.*s\n", name, (int)size, (const char *)value);
    }
}

void print_archive_ret(struct archive *a, int ret, char * msg, bool ARCHIVE_OK_invalid = false, bool ARCHIVE_EOF_invalid=false) {    
    switch (ret) {
        case ARCHIVE_OK:
            fprintf(stderr, "%s %s [ARCHIVE_OK] %s\n",
                ARCHIVE_OK_invalid? "[ERROR]": "[INFO]",
                msg,
                ARCHIVE_OK_invalid? "(not expected, investigate)": "");
            break;
        case ARCHIVE_WARN:
            fprintf(stderr, "[ERROR] %s [ARCHIVE_WARN] %s\n", msg, archive_error_string(a));
            break;
        case ARCHIVE_EOF:
            fprintf(stderr, "%s %s [ARCHIVE_EOF] %s\n",
                ARCHIVE_EOF_invalid? "[ERROR]": "[INFO]",
                msg, archive_error_string(a));
            break;
        case ARCHIVE_RETRY:
            fprintf(stderr, "[ERROR] %s [ARCHIVE_RETRY] %s\n", msg, archive_error_string(a));
            break;
        case ARCHIVE_FATAL:
            fprintf(stderr, "[ERROR] %s [ARCHIVE_FATAL] %s\n", msg, archive_error_string(a));
            break;
        default:
            fprintf(stderr, "[ERROR] %s [UNKNOWN] %s\n", msg, archive_error_string(a));
            break;
    }
}


int main(int argc, char **argv) {
    // printf("Libarchive details: %s\n", archive_version_details());
    // printf("\tarchive_zlib_version: %s\n", archive_zlib_version());
    // printf("\tarchive_liblzma_version: %s\n", archive_liblzma_version());
    // printf("\tarchive_bzlib_version: %s\n", archive_bzlib_version());
    // printf("\tarchive_liblz4_version: %s\n", archive_liblz4_version());
    // printf("\tarchive_libzstd_version: %s\n", archive_libzstd_version());
    // printf("\tLibrary version (archive_version_number()): %lld\n", archive_version_number());
    // printf("\tInstalled header version (ARCHIVE_VERSION_NUMBER): %lld\n", ARCHIVE_VERSION_NUMBER );
    // printf("\tarchive_version_string(): %s\n", archive_version_string());
    if (argc != 2) {
        dprint(stderr, "Usage: %s <rar-file>\n", argv[0]);
        return 1;
    }

    int libarchive_ret = ARCHIVE_OK;
    
    printf("###############################################\n");
    struct archive *a;
    struct archive_read** ar;
    struct archive *output;
    struct archive_entry *entry;
    int ret;
    size_t size;
    int64_t offset;
    rar_type_found = 0;

    a = archive_read_new();    
    archive_read_support_filter_all(a); // enable decompression filters, i.e. gzip, bzip2, xz, etc
    // archive_read_support_format_all(a);
    archive_read_support_format_rar(a); // https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_support_format_rar.c
    archive_read_support_format_rar5(a); // https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_support_format_rar5.c
    archive_read_support_compression_all(a);
    // print_archive_ret(
    //     a,
    //     archive_read_set_options(a, "hdrcharset=CP936"),
    //     "Setting hdrcharset:"
    // );
    
    
    // // shortcut with canned callbacks
    // ret = archive_read_open_filename(a, argv[1], 10240);
    // if (ret != ARCHIVE_OK) {
        //     dprint(stderr, "Failed to open archive: %s\n", archive_error_string(a));
        //     archive_read_free(a);
        //     return 1;
        // }
    strcpy(archive_name, argv[1]);

    fprintf(stdout, "Processing: %s\n", archive_name);

    FILE *file = fopen(archive_name, "rb");
    if (!file) {
        dprint(stderr, "Failed to open archive: %s\n", archive_name);
        return 1;
    }
    //--> Get archive/file size
    fseek(file, 0, SEEK_END);
    size_t sz = ftell(file);
    rewind(file);
    printf("File size: %ld bytes\n", size);
    uint8_t * buff = (uint8_t *) calloc(sz, sizeof(uint8_t));
    size_t bytes_read = 0;
    bytes_read = fread(buff, 1, sizeof(buff), file);
    rewind(file);
    //--> END: Get archive/file size

    archive_read_open(
        a, 
        file,
        my_open_callback, // open callback must return 0, otherwise unpacking stops
        my_read_callback,
        my_close_callback
    ); // Sets up callbacks, sets data in dataset at index 0, determines filters (choose_filters()) and format (choose_formats()), but does not read the data
    dprint(stderr, "###############################################\n");
    // archive_read_set_read_callback(a, my_read_callback);
    dprint(stderr, "Archive format code: %d, name: %s\n", archive_format(a), archive_format_name(a));
    dprint(stderr, "archive_read_header_position(): %lld\n", archive_read_header_position(a));
    dprint(stderr, "\narchive_read_has_encrypted_entries(): %lld\n", archive_read_has_encrypted_entries(a));
    switch (archive_read_has_encrypted_entries(a)) {
        case ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED:
            dprint(stderr, "ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED\n");
            break;
        // case ARCHIVE_READ_FORMAT_ENCRYPTION_NONE:
        //     dprint(stderr, "ARCHIVE_READ_FORMAT_ENCRYPTION_NONE\n");
        //     break;
        case ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW:
            dprint(stderr, "ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW\n");
            break;
        // case ARCHIVE_READ_FORMAT_ENCRYPTION_YES:
        //     dprint(stderr, "ARCHIVE_READ_FORMAT_ENCRYPTION_YES\n");
        //     break;
        default:
            dprint(stderr, "Unknown encryption status\n");
    }
    dprint(stderr, "\narchive_read_format_capabilities(): %lld\n", archive_read_format_capabilities(a));
    switch(archive_read_format_capabilities(a)) {
        case ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_DATA:
            dprint(stdout, "ARCHIVE_FORMAT_CAPS_ENCRYPTION\n");
            break;
        case ARCHIVE_READ_FORMAT_CAPS_NONE :
            dprint(stderr, "ARCHIVE_READ_FORMAT_CAPS_NONE \n");
            break;
        default:
            dprint(stderr, "Unknown encryption capability\n");
    }
    dprint(stderr, "archive_filter_count(): %d\n", archive_filter_count(a));
    dprint(stderr, "archive_filter_code(): %d\n", archive_filter_code(a, 0));
    dprint(stderr, "compression name / archive_filter_name(): %s\n", archive_filter_name(a, 0));
    dprint(stderr, "archive_file_count(): %d\n", archive_file_count(a));
    // --> Exp manually read and seek bytes from archive

    // char buff[100];
    // size_t bytes_read = archive_read_data(a, buff, 100); // behaves like read() in linux, need to reset seek()
    // printf("\narchive_read_data(archive, bufffer, 100):\n\t");
    // for (int i = 0;i < bytes_read && i < 100; i++) {
    //     printf("%02x ", (unsigned char)buff[i]);
    // } printf("\n");

    // int seek_ret = archive_seek_data(a, 0, SEEK_SET); // did not work
    // switch(seek_ret) {
    //     case EBADF:
    //         dprint(stderr, "Could not reset seek: EBADF\n");
    //     case EINVAL:
    //         dprint(stderr, "Could not reset seek: EINVAL\n");
    //     case ENXIO:
    //         dprint(stderr, "Could not reset seek: ENXIO\n");
    //     case EOVERFLOW:
    //         dprint(stderr, "Could not reset seek: EOVERFLOW\n");
    //     case ESPIPE:
    //         dprint(stderr, "Could not reset seek: ESPIPE\n");
    //     default:
    //         dprint(stderr, "Could not reset seek: unknown error\n");
    // }

    // --> END: Exp manually read and seek bytes from archive

    // --> Trying to read archive headers using libarchive private code as ref

    // struct archive_read* ar;
    // *ar = (struct archive_read*) a;
    // if(ARCHIVE_OK != (ret = get_archive_read(a, &ar))) {
    //     dprint(stderr, "Failed to get archive read: %s\n", archive_error_string(a));
    // }

    // --> END: Trying to read archive headers using libarchive private code as ref

    // Prepare output archive for extraction
    int flags = ARCHIVE_EXTRACT_TIME 
        | ARCHIVE_EXTRACT_PERM 
        | ARCHIVE_EXTRACT_ACL 
        | ARCHIVE_EXTRACT_FFLAGS
        | ARCHIVE_EXTRACT_OWNER
        | ARCHIVE_EXTRACT_XATTR;
    
    output = archive_write_disk_new();
    archive_write_disk_set_options(output, flags);

    fprintf(stdout, "###############################################\n");
    printf("Starting reading archive entries...\n");
    while (true) {
        fprintf(stdout, "==============================================#\n");

        ret = archive_read_next_header(a, &entry);
        if (ret != ARCHIVE_OK) {
            print_archive_ret(a, ret, "archive_read_next_header()");
            libarchive_ret = ret;
            break;
        }
        const char * pathname = archive_entry_pathname(entry);
        printf("Processing: %s\n", pathname);
        // Check for "CMT" header or specific metadata
        printf("Extended attributes:\n");
        process_xattrs(entry);
        // Print header field values
        printf("File: %s\n", archive_entry_pathname(entry));
        printf("Size: %ld bytes\n", archive_entry_size(entry));
        printf("Mode: %o\n", archive_entry_mode(entry));
        printf("UID: %d\n", archive_entry_uid(entry));
        printf("GID: %d\n", archive_entry_gid(entry));
        printf("Last Modified: %ld\n", archive_entry_mtime(entry));
        // printf("archive_entry_birthtime_is_set: %d\n", archive_entry_birthtime_is_set(entry));
        // printf("archive_entry_birthtime(): %lld\n", archive_entry_birthtime(entry));
        // printf("archive_entry_fflags_text(): %s\n", archive_entry_fflags_text(entry));
        // printf("archive_entry_filetype(): %d\n", archive_entry_filetype(entry));
        // printf("archive_entry_nlink(): %d\n", archive_entry_nlink(entry));
        // printf("archive_entry_is_encrypted(): %d\n", archive_entry_is_encrypted(entry));
        // printf("archive_entry_hardlink(): %s\n", archive_entry_hardlink(entry));
        // printf("archive_entry_symlink(): %s\n", archive_entry_symlink(entry));
        // printf("archive_entry_gname(): %s\n", archive_entry_gname);
        // printf("archive_entry_uname(): %s\n", archive_entry_uname(entry));
        // printf("archive_entry_devmajor(): %d\n", archive_entry_devmajor(entry));
        // printf("archive_entry_devminor(): %d\n", archive_entry_devminor(entry));
        // printf("archive_entry_rdevmajor(): %d\n", archive_entry_rdevmajor(entry));
        // printf("archive_entry_rdevminor(): %d\n", archive_entry_rdevminor(entry));
        // printf("archive_entry_atime(): %lld\n", archive_entry_atime(entry));
        // printf("archive_entry_ctime(): %lld\n", archive_entry_ctime(entry));    
        // auto generic_header = entry->generic; // did not work (incomplete type archive entry, forward declaration)

        archive_entry * dup_entry = archive_entry_clone(entry);
        dprint(stderr, "Clone entry: %s\n", archive_entry_pathname(dup_entry));
        dprint(stderr, "Clone entry size: %ld bytes\n", archive_entry_size(dup_entry)); 

        // // --> Extract using archive_read_extract()
        // ret = archive_read_extract(a, entry, flags);
        // if (ret != ARCHIVE_OK) {
        //     dprint(stderr, "Failed to extract %s: %s\n", pathname, archive_error_string(a));
        // }
        // archive_read_data_skip(a);
        // // -> END: Extract using archive_read_extract()
        // --> Extract using archive_write_header(), archive_write_data_block() WORKS
        
        ret = archive_write_header(output, entry);
        if (!strcmp(pathname, "CMT")) {
            // archive_entry_set_pathname(entry, "_cmt_");

            // By default, files are extracted, not skipped
            // archive_read_data_skip(a);
            fprintf(stdout, "---- CMT content ----\n");
            ret = archive_read_data_into_fd(a, STDOUT_FILENO);
            fprintf(stdout, "---------------------\n");
        }
        if (true) {
            // Copy data from archive to output
            const void *buffer;
            size_t size;
            la_int64_t offset;
            while (true) {
                ret = archive_read_data_block(a, &buffer, &size, &offset);
                if (ret == ARCHIVE_OK) {
                    dprint(stderr, "[DEBUG] archive_read_data_block() size: %ld, offset: %ld\n", size, offset);
                    break;
                    archive_write_data_block(output, buffer, size, offset);
                } else {
                    print_archive_ret( a, ret, "archive_read_data_block():");
                    libarchive_ret = ret;
                }
                break;
            }
            archive_write_finish_entry(output);
        }
        // --> END: Extract using archive_write_header(), archive_write_data_block()
    }
    print_archive_ret( a, ret, "Return from last archive_read_next_header():", true);
    archive_read_close(a);
    ret = archive_read_free(a);
    if (ret != ARCHIVE_OK) {
        dprint(stderr, "Failed to free archive: %s\n", archive_error_string(a));
        libarchive_ret = ret;
    }
    // fclose(file);

    fprintf(stderr, "Return from Libarchive: %d\n", libarchive_ret);

    if (libarchive_ret != ARCHIVE_OK) {
        return libarchive_ret;
    }
    return 0;
}