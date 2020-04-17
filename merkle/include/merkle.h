/* reference: RFC 6962 (Certificate Transparency) sect 2.1 (Merkle hash trees)
 * https://tools.ietf.org/html/rfc6962#section-2.1
 */

#ifndef MERKLE_H
#define MERKLE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include <endian.h>

#include <openssl/evp.h>

typedef unsigned char digest_t[EVP_MAX_MD_SIZE];

typedef struct {
  /* parameters, unchanging */
  uint32_t block_size;
  uint32_t hash_nid;

  /* properties of current storage state */
  uint64_t size;
  digest_t root;

  /* derived values, saved for efficiency */
  uint64_t nblocks;
  const EVP_MD *md_alg;
  uint32_t hash_size;
  digest_t signature;
} store_info_t;

typedef struct {
  uint32_t nhash, nblock;
  EVP_MD_CTX *ctx;
  uint64_t *hash_ind;
  digest_t *hashes;
  char *blocks;
} work_space_t;

typedef struct {
  char *buf;
  uint64_t count;
  uint64_t offset;

  uint32_t nhash;
  uint64_t *hash_ind;
  digest_t *hashes;

  uint64_t block_count;
  uint64_t block_offset;
  char *first_block;
  char *middle_blocks;
  char *last_block;
  uint32_t lbsize;
} read_req_t;

#define READ_OP (1)

void init_work_space(const store_info_t *info, work_space_t *space);

void clear_work_space(work_space_t *space);

/* makes sure the work space is large enough for the given info */
void ensure_space(const store_info_t *info, work_space_t *space);

/* sets info->signature */
void update_signature(store_info_t *info, EVP_MD_CTX *ctx);

/* updates info->nblocks and ensures sufficient work space according to info->size */
static inline void store_info_newsize(store_info_t *info, work_space_t *space) {
  info->nblocks = (info->size - 1) / info->block_size + 1;
  ensure_space(info, space);
}

/* assumes block_size, hash_nid, size, and root are set already.
 * sets all other fields. */
void store_info_fillin(store_info_t *info);

/* assumes info->size is set, and sets all other fields except the root and signature. */
void store_info_default(store_info_t *info);

/* stores the data in store_info_t *info to the FILE *out.
 * If include_root is zero, then the root hash is not written.
 * A count of the total number of bytes written is returned.
 */
int store_info_store(FILE *out, bool include_root, const store_info_t *info);

/* loads the data in store_info_t *info from the FILE *in.
 * If include_root is zero, then the root hash is not read.
 * A count of the total number of bytes read is returned.
 */
int store_info_load(FILE *in, bool include_root, store_info_t *info);


void print_hash(const char *before, const digest_t hash, const char *after,
    FILE *out, const store_info_t *info);

void hash_leaf(digest_t dest, const char *restrict block, uint32_t bsize,
    const store_info_t *info, EVP_MD_CTX *ctx);

void hash_internal(digest_t dest, const digest_t child1, const digest_t child2,
    const store_info_t *info, EVP_MD_CTX *ctx);

/* sets root and also updates signature; assumes all other parameters are set
 * INCLUDING info->size which must match the data available on FILE *in.
 * If FILE *out is non-NULL, the tree of hashes is written there.
 */
void init_root(FILE *in, FILE *out, store_info_t *info, work_space_t *space);

void pre_read(read_req_t *rreq, char *buf, uint32_t count, uint64_t offset,
    const store_info_t *info, work_space_t *space);

bool post_read(read_req_t *rreq, const store_info_t *info, work_space_t *space);

#endif /* MERKLE_H */
