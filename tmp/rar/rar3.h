// RAR version 3.93

#ifndef RAR3_HANDLER
#define RAR3_HANDLER

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>

namespace rar4 {

/* File Header Flags */
#define FHD_SPLIT_BEFORE 0x0001
#define FHD_SPLIT_AFTER  0x0002
#define FHD_PASSWORD     0x0004
#define FHD_COMMENT      0x0008
#define FHD_SOLID        0x0010
#define FHD_LARGE        0x0100
#define FHD_UNICODE      0x0200
#define FHD_SALT         0x0400
#define FHD_VERSION      0x0800
#define FHD_EXTTIME      0x1000
#define FHD_EXTFLAGS     0x2000

enum HEADER_TYPE {
  // RAR 1.5 - 4.x header types.
  HEAD3_MARK        = 0x72, // marker block
  HEAD3_MAIN        = 0x73, // archive header
  HEAD3_FILE        = 0x74, // file header
  HEAD3_CMT         = 0x75, // old style comment header
  HEAD3_AV          = 0x76, // old style authenticity information
  HEAD3_OLDSERVICE  = 0x77, // old style subblock
  HEAD3_PROTECT     = 0x78, // old style recovery record
  HEAD3_SIGN        = 0x79, // old style authenticity information
  HEAD3_SERVICE     = 0x7a, // subblock
  HEAD3_ENDARC      = 0x7b  // 
};

/* Fields common to all headers */
struct rar_header {
  char crc[2];
  char type;
  char flags[2];
  char size[2];
};

/* Fields common to all file headers, including new subblock that contain CMT */
struct rar_file_header
{
  char pack_size[4];
  char unp_size[4];
  char host_os;
  char file_crc[4];
  char file_time[4];
  char unp_ver;
  char method;
  char name_size[2];
  char file_attr[4];
};

const uint8_t signature_rar4[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}; //{'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};


bool is_valid_signature(const void *p) {
    return memcmp(p, signature_rar4, sizeof(signature_rar4)) == 0;
}

static inline uint16_t archive_le16dec(const void *pp) {
	unsigned char const *p = (unsigned char const *)pp;
	/* Store into unsigned temporaries before left shifting, to avoid
	promotion to signed int and then left shifting into the sign bit,
	which is undefined behaviour. */
	unsigned int p1 = p[1];
	unsigned int p0 = p[0];
	return ((p1 << 8) | p0);
}

void parse_cmt(void ** cmt_buffer, size_t * cmt_buffer_sz, const uint8_t * buf, size_t sz) {

}

}

#endif