#ifndef RAR5_HANDLER
#define RAR5_HANDLER

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include "../utils.h"
namespace rar5 {

// RAR5 headers must not exceed 2 MB.
#define MAX_HEADER_SIZE_RAR5 0x200000 // unrar src

const uint8_t signature_rar5[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}; //{'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};

enum HEADER_TYPE {
  // RAR 5.0 header types.
  HEAD_MARK=0x00, HEAD_MAIN=0x01, HEAD_FILE=0x02, HEAD_SERVICE=0x03,
  HEAD_CRYPT=0x04, HEAD_ENDARC=0x05, HEAD_UNKNOWN=0xff,
};

enum HEADER_FLAG {
	EXTRA_AREA=0x01, DATA_AREA=0x02
};

enum FILE_FLAG {
	TIME_FIELD_UNIX_FORMAT_PRESENT=0x02, DATA_CRC32_PRESENT=0x04
};

#define SUBHEAD_TYPE_CMT      "CMT"
#define SUBHEAD_TYPE_QOPEN    "QO"
#define SUBHEAD_TYPE_ACL      "ACL"
#define SUBHEAD_TYPE_STREAM   "STM"
#define SUBHEAD_TYPE_UOWNER   "UOW"
#define SUBHEAD_TYPE_AV       "AV"
#define SUBHEAD_TYPE_RR       "RR"
#define SUBHEAD_TYPE_OS2EA    "EA2"

struct rar5_general_header {
	uint32_t crc32;
	uint32_t sz; // Header size must not occupy more than 3 variable length integer bytes, resulting in 2 MB maximum header size (MAX_HEADER_SIZE_RAR5)
	uint64_t type; // Although there are only 5 types, max value of vint can be 64 bit (10 bytes)
	uint64_t flags;
	uint64_t extra_area_sz;
	uint64_t data_area_sz;
	uint8_t * extra_area;
	uint8_t * data_area;

	size_t sz_numbytes;
	size_t type_num_bytes;
	size_t start_pos;
	size_t flags_num_bytes;
};

// for extra area and data area
// data area not counted in Header CRC and Header size fields.
struct rar5_optional_area {
	uint64_t sz;
	void * area;

	size_t sz_numbytes;
};

struct cmp_info_details {
	uint32_t algo_version; // Version 0 archives can be unpacked by RAR 5.0 and newer. Version 1 archives can be unpacked by RAR 7.0 and newer.
	bool solid; //  It can be set only for file headers and is never set for service headers.
	uint32_t method; // Currently only values 0 - 5 are used. 0 means no compression.
	
	uint32_t min_dictionary_sz; // minimum dictionary size required to extract data, 128 KB * 2^N
	// 0 means 128 KB, 1 - 256 KB, ..., 15 - 4096 MB, ..., 19 - 64 GB. 23 means 1 TB, 
	// Values above 15 are used only if compression algorithm version is 1
	uint32_t v1_compression_buffer;
	bool v1_dict_but_uses_v0_compression_algo;
};

void parse_compression_info(cmp_info_details * details, uint64_t compression_info) {
	details->algo_version = compression_info & 0x003f;
	details->solid = compression_info & 0x0040;
	details->method= compression_info & 0x0380;
	details->min_dictionary_sz = compression_info & 0x7c00;
	details->v1_compression_buffer = compression_info & 0xf8000;
	details->v1_dict_but_uses_v0_compression_algo = compression_info & 0x100000;
}

void print_compression_info(const cmp_info_details & details) {
	dprint(stderr, "[DEBUG] compression info details:\n");
	dprint(stderr, "\talgo_version: 0x%02x (%d)\n", details.algo_version, details.algo_version);
	dprint(stderr, "\tsolid: 0x%02x (%d)\n", details.solid, details.solid);
	dprint(stderr, "\tmethod: 0x%02x (%d)\n", details.method, details.method);
	dprint(stderr, "\tmin_dictionary_sz: 0x%02x (%d)\n", details.min_dictionary_sz, details.min_dictionary_sz);
	dprint(stderr, "\tv1_compression_buffer: 0x%02x (%d)\n", details.v1_compression_buffer, details.v1_compression_buffer);
	dprint(stderr, "\tv1_dict_but_uses_v0_compression_algo: 0x%02x (%d)\n", details.v1_dict_but_uses_v0_compression_algo, details.v1_dict_but_uses_v0_compression_algo);
}


// File header, service header
struct file_svc_header_info {
	rar5_optional_area extra_area;
	rar5_optional_area data_area;
	uint64_t file_flags;
	uint64_t unpacked_size;
	uint64_t attributes;
	uint32_t mtime; // File modification time in Unix time format. Optional, present if 0x0002 file flag is set.
	uint32_t data_crc32;
	uint64_t compression_info;
	uint64_t host_os;
	uint64_t name_length;
	char * name;


	size_t file_flags_numbytes;
	size_t unpacked_size_numbytes;
	size_t attributes_numbytes;
	size_t compression_info_numbytes;
	size_t host_os_numbytes;
	size_t name_length_numbytes;
	size_t name_numbytes;
	bool cmt_found;

	cmp_info_details compression_info_details;
};

struct end_of_archive_info {
	uint64_t end_of_archive_flags;

	size_t end_of_archive_flags_numbytes;
};

uint32_t raw_get4(const uint8_t * p) {
#if defined(BIG_ENDIAN) || !defined(ALLOW_MISALIGNED)
	return p[0] 
		+ ((uint32_t)p[1] << 8) 
		+ ((uint32_t)p[2] << 16) 
		+ ((uint32_t)p[3] << 24);
#else
	return *(uint32_t *)p;
#endif
}

uint32_t get_uint32(const uint8_t * p) {
	if (p)
		return raw_get4(p);
	return 0;
}

uint64_t get_variable_int(const uint8_t * p) {
	uint64_t res = 0;
	for (int i = 0, shift = 0; i < 10 && shift < 64; shift += 7, i ++) {
		uint8_t cur = *p;
		res += static_cast<uint64_t>(cur & 0x7f) << shift;
		if ((cur & 0x80) == 0)
			return res;
		p ++;
	}
	return 0; // out of buffer border
}

uint8_t get_num_bytes_variable_int(const uint8_t * p) {
	for (int i = 0; i < 10; i ++) {
		uint8_t cur = *p;
		if ((cur & 0x80) == 0)
			return i+1;
		p ++;
	}
	return 0; // out of buffer border
}

bool is_valid_signature(const void *buffer) {
    return memcmp(buffer, signature_rar5, sizeof(signature_rar5)) == 0;
}

void parse_rar5_general_headers(
    const uint8_t * p,
    const size_t start_pos = 0,
    rar5_general_header * hdr = NULL
) {
    // Returns the end position of the current general header
    size_t pos = start_pos;
    // 0x75 0x61 0x53 0x40
    uint32_t hdr_crc32 = get_uint32(p + pos);
    dprint(stderr, "[DEBUG] hdr_crc32: 0x%02x\n", hdr_crc32);
    pos += sizeof(hdr_crc32); 
    uint64_t hdr_size = get_variable_int(p + pos);
    size_t hdr_num_bytes = get_num_bytes_variable_int(p + pos);
    dprint(stderr, "[DEBUG] Header size: 0x%02x (%d), hdr_num_bytes: %d\n", hdr_size, hdr_size, hdr_num_bytes);
    if (!hdr_num_bytes || !hdr_size) {
        dprint(stderr, "[ERROR]: header size parsed to be zero.\n");
    }
    pos += hdr_num_bytes; 
    
    uint64_t hdr_type = get_variable_int(p + pos);
    size_t hdr_type_num_bytes = get_num_bytes_variable_int(p + pos);
    dprint(stderr, "[DEBUG] hdr_type: 0x%02x, hdr_type_num_bytes: %d\n", hdr_type, hdr_type_num_bytes);
    if (!hdr_num_bytes || !hdr_size) {
        dprint(stderr, "[ERROR]: header type parsed to be zero.\n");
    }
    pos += hdr_type_num_bytes;

    uint64_t hdr_flags = get_variable_int(p + pos);
    size_t hdr_flags_num_bytes = get_num_bytes_variable_int(p + pos);
    dprint(stderr, "[DEBUG] hdr_flags: 0x%02x, hdr_flags_num_bytes: %d\n", hdr_flags, hdr_flags_num_bytes);
    if (!hdr_num_bytes || !hdr_size) {
        dprint(stderr, "[ERROR]: header flags parsed to be zero.\n");
    }
    pos += hdr_flags_num_bytes;
    if (hdr) {
        hdr->start_pos = start_pos;
        hdr->crc32 = hdr_crc32;
        hdr->sz = hdr_size;
        hdr->sz_numbytes = hdr_num_bytes;
        hdr->type = hdr_type;
        hdr->type_num_bytes = hdr_type_num_bytes;
        hdr->flags = hdr_flags;
        hdr->flags_num_bytes = hdr_flags_num_bytes;
    }
}

size_t parse_rar5_main_header(
    const uint8_t * p,
    rar5_general_header * hdr,
    size_t start_pos = 0
) { 
    size_t curpos = start_pos + sizeof(signature_rar5);
    parse_rar5_general_headers(p, curpos, hdr);
    if (hdr->type != HEAD_MAIN) {
        dprint(stderr, "[ERROR] Type field of intended (first) block is not main header.");
    }
    curpos += (hdr->sz + hdr->sz_numbytes + 4); // main header does not data area, so we can jump directly.
    return curpos;
}

void parse_cmt(void ** cmt_buffer, size_t * cmt_buffer_sz, const uint8_t * buf, size_t sz) {
	rar5_general_header gen_main_hdr;
    size_t curpos = parse_rar5_main_header((uint8_t *)buf, &gen_main_hdr);
    dprint(stderr, "parse_rar5_main_header(): curpos after main header %d\n", curpos);
    int blkcnt = 2; // 1 is for main header
    bool cmt_found = false; // no need to continue once found
    while (curpos < sz && !cmt_found) {
        dprint(stderr, "=======================================\n");
        dprint(stderr, "Block %d: curpos: 0x%02x (%d)\n", blkcnt, curpos, curpos);
        rar5_general_header hdr;
        parse_rar5_general_headers(buf, curpos, &hdr);
        dprint(stderr, "Block type: %s\n", hdr.type == HEAD_SERVICE? 
            "Service": hdr.type == HEAD_FILE? 
                "File": hdr.type == HEAD_ENDARC? 
                    "End of archive": "unknown");
        
        size_t hdr_info_pos = curpos + sizeof(hdr.crc32) +  hdr.sz_numbytes + hdr.type_num_bytes + hdr.flags_num_bytes;

        if (hdr.type == HEAD_ENDARC) {
            end_of_archive_info hdr_info{};
            hdr_info.end_of_archive_flags = get_variable_int(buf + hdr_info_pos);
            hdr_info.end_of_archive_flags_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
            dprint(stderr, "[DEBUG] end_of_archive_flags sz: 0x%02x (%d), sz_numbytes: %d\n",
                hdr_info.end_of_archive_flags, hdr_info.end_of_archive_flags, hdr_info.end_of_archive_flags_numbytes);
            hdr_info_pos += hdr_info.end_of_archive_flags_numbytes;
            if (hdr_info.end_of_archive_flags & 0x01) {
                dprint(stderr, "[DEBUG] End of archive is indicating that the current one is part of a volume (not the last one).");
            }
            hdr_info_pos += hdr_info.end_of_archive_flags_numbytes;
        } else if (hdr.type == HEAD_SERVICE || hdr.type == HEAD_FILE) {
            file_svc_header_info hdr_info{};
            
            if (hdr.flags & EXTRA_AREA) {
                hdr_info.extra_area.sz = get_variable_int(buf + hdr_info_pos);
                hdr_info.extra_area.sz_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
                dprint(stderr, "[DEBUG] extra_area sz: 0x%02x (%d), sz_numbytes: %d\n",
                    hdr_info.extra_area.sz, hdr_info.extra_area.sz, hdr_info.extra_area.sz_numbytes);
                hdr_info_pos += hdr_info.extra_area.sz_numbytes;
            }

            if (hdr.flags & DATA_AREA) {
                dprint(stderr, "[DEBUG] Parse data area size, bytes: ");
                for (int i = 0; i < 8; i ++) {
                    dprint(stderr, "0x%02x ", *(buf + hdr_info_pos + i));
                } dprint(stderr, "\n");
                hdr_info.data_area.sz = get_variable_int(buf + hdr_info_pos);
                hdr_info.data_area.sz_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
                dprint(stderr, "[DEBUG] data_area sz: 0x%02x (%d), sz_numbytes: %d\n",
                    hdr_info.data_area.sz, hdr_info.data_area.sz, hdr_info.data_area.sz_numbytes);
                hdr_info_pos += hdr_info.data_area.sz_numbytes;
            }
            
            hdr_info.file_flags = get_variable_int(buf + hdr_info_pos);
            hdr_info.file_flags_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
            dprint(stderr, "[DEBUG] file_flags: 0x%02x, sz_numbytes: %d\n",
                hdr_info.file_flags, hdr_info.file_flags_numbytes);
            hdr_info_pos += hdr_info.file_flags_numbytes;
            
            hdr_info.unpacked_size = get_variable_int(buf + hdr_info_pos);
            hdr_info.unpacked_size_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
            dprint(stderr, "[DEBUG] unpacked_size: 0x%02x (%d), sz_numbytes: %d\n",
                hdr_info.unpacked_size, hdr_info.unpacked_size, hdr_info.unpacked_size_numbytes);
            hdr_info_pos += hdr_info.unpacked_size_numbytes;

            hdr_info.attributes = get_variable_int(buf + hdr_info_pos);
            hdr_info.attributes_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
            dprint(stderr, "[DEBUG] attributes: 0x%02x (%d), sz_numbytes: %d\n",
                hdr_info.attributes, hdr_info.attributes, hdr_info.attributes_numbytes);
            hdr_info_pos += hdr_info.attributes_numbytes;
            
            if (hdr_info.file_flags & TIME_FIELD_UNIX_FORMAT_PRESENT) {
                hdr_info.mtime = get_uint32(buf + hdr_info_pos);
                dprint(stderr, "[DEBUG] mtime: 0x%02x (%d), sz_numbytes: %d\n",
                    hdr_info.mtime, hdr_info.mtime, sizeof(hdr_info.mtime));
                hdr_info_pos += sizeof(hdr_info.mtime);
            }

            if (hdr_info.file_flags & DATA_CRC32_PRESENT) {
                dprint(stderr, "[DEBUG] Parse data crc32, bytes: ");
                for (int i = 0; i < 8; i ++) {
                    dprint(stderr, "0x%02x ", *(buf + hdr_info_pos + i));
                } dprint(stderr, "\n");
                hdr_info.data_crc32 = get_uint32(buf + hdr_info_pos);
                dprint(stderr, "[DEBUG] data_crc32: 0x%02x (%d)\n", hdr_info.data_crc32, hdr_info.data_crc32);
                hdr_info_pos += sizeof(hdr_info.data_crc32);
            }

            hdr_info.compression_info = get_variable_int(buf + hdr_info_pos);
            hdr_info.compression_info_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
            dprint(stderr, "[DEBUG] compression_info: 0x%02x (%d), sz_numbytes: %d\n",
                hdr_info.compression_info, hdr_info.compression_info, hdr_info.compression_info_numbytes);
            hdr_info_pos += hdr_info.compression_info_numbytes;
            parse_compression_info(&hdr_info.compression_info_details, hdr_info.compression_info);
            print_compression_info(hdr_info.compression_info_details);
            
            hdr_info.host_os = get_variable_int(buf + hdr_info_pos);
            hdr_info.host_os_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
            dprint(stderr, "[DEBUG] host_os: 0x%02x (%d), sz_numbytes: %d\n",
                hdr_info.host_os, hdr_info.host_os, hdr_info.host_os_numbytes);
            hdr_info_pos += hdr_info.host_os_numbytes;

            hdr_info.name_length = get_variable_int(buf + hdr_info_pos);
            hdr_info.name_length_numbytes = get_num_bytes_variable_int(buf + hdr_info_pos);
            dprint(stderr, "[DEBUG] name_length: 0x%02x (%d), sz_numbytes: %d\n",
                hdr_info.name_length, hdr_info.name_length, hdr_info.name_length_numbytes);
            hdr_info_pos += hdr_info.name_length_numbytes;

            hdr_info.name = (char *)calloc(9, sizeof(char));
            dprint(stderr, "[DEBUG] sizeof(hdr_info.name): %d,strlen(hdr_info.name): %d\n", sizeof(hdr_info.name), strlen(hdr_info.name));
            memcpy(hdr_info.name, buf+hdr_info_pos, hdr_info.name_length);
            hdr_info_pos += hdr_info.name_length;
            dprint(stderr, "[DEBUG] name: %s, strlen(hdr_info.name): %d, hdr_info.name_length: %d\n",
                hdr_info.name, strlen(hdr_info.name), hdr_info.name_length);

            if (hdr.flags & EXTRA_AREA) {
                dprint(stderr, "[DEBUG] skipping extra area\n");
                hdr_info_pos += hdr_info.extra_area.sz;
            }
            if (hdr.flags & DATA_AREA) {
                dprint(stderr, "[DEBUG] data area:\n\t");
                for (int i = 0; i < 32; i ++) {
                    dprint(stderr, "0x%02x ", *(buf + hdr_info_pos + i));
                } dprint(stderr, "\n");
                if (hdr.type == HEAD_SERVICE) {
                    if (!strncmp(hdr_info.name, SUBHEAD_TYPE_CMT, strlen(SUBHEAD_TYPE_CMT))) {
                        // parse only if CMT
                        dprint(stderr, "[DEBUG] CMT found!\n");
                        hdr_info.cmt_found = true;
                        *cmt_buffer = calloc(hdr_info.data_area.sz, sizeof(char));
						*cmt_buffer_sz = hdr_info.data_area.sz;
                        memcpy(*cmt_buffer, buf + hdr_info_pos, *cmt_buffer_sz);
						hdr_info.data_area.area = *cmt_buffer;
                        dprint(stderr, "[DEBUG] data_area.area:\n%s\n", (char *)hdr_info.data_area.area);
                        dprint(stderr, "[DEBUG] strlen(hdr_info.data_area.area): %d\n\thdr_info.data_area.sz: %d\n",
                            strlen((char *)hdr_info.data_area.area), hdr_info.data_area.sz);
                        // cmnt_found = true;
                    }
                }
                dprint(stderr, "[DEBUG] hdr_info_pos: 0x%02x (%d)\n", hdr_info_pos, hdr_info_pos);
            }
            hdr_info_pos += hdr_info.data_area.sz;
            // checks
            if (hdr.type == HEAD_SERVICE) {
                if (!strncmp(hdr_info.name, SUBHEAD_TYPE_CMT, strlen(SUBHEAD_TYPE_CMT))) {
                    dprint(stderr, "[DEBUG] Service header type: CMT: Archive comment\n");
                    if (hdr.flags & DATA_AREA) {
                        dprint(stderr, "[WARN] Block type is service and name is CMT but data area not found.\n");
                }
                } else if (!strncmp(hdr_info.name, SUBHEAD_TYPE_QOPEN, strlen(SUBHEAD_TYPE_QOPEN))) {
                    dprint(stderr, "[DEBUG] Service header type: QO: Archive quick open data\n");
                } else if (!strncmp(hdr_info.name, SUBHEAD_TYPE_ACL, strlen(SUBHEAD_TYPE_ACL))) {
                    dprint(stderr, "[DEBUG] Service header type: ACL: NTFS file permissions\n");
                } else if (!strncmp(hdr_info.name, SUBHEAD_TYPE_STREAM, strlen(SUBHEAD_TYPE_STREAM))) {
                    dprint(stderr, "[DEBUG] Service header type: STM: NTFS alternate data stream\n");
                } else if (!strncmp(hdr_info.name, SUBHEAD_TYPE_RR, strlen(SUBHEAD_TYPE_RR))) {
                    dprint(stderr, "[DEBUG] Service header type: RR: Recovery record\n");
                } else {
                    dprint(stderr, "[WARN] Unknown service header type: %s\n", hdr_info.name);
                }
            }
        }
        dprint(stderr, "[DEBUG] hdr_info_pos: 0x%02x (%d)\n", hdr_info_pos, hdr_info_pos);
        curpos = hdr_info_pos;
        blkcnt ++;
    }
	dprint(stderr, "---------------------------------------\n");
    dprint(stderr, "Number of blocks: %d\n", blkcnt);
	dprint(stderr, "=======================================\n");
}

}
#endif