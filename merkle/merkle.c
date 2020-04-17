#include "merkle.h"

#define EMSG(msg) do { \
  fprintf(stderr, "error %s line %d: " msg "\n", __FILE__, __LINE__); \
  abort(); \
} while(0)

// bit length of a uint64_t
#define BITLEN64(x) \
  (64 - __builtin_clzll(x))

// number of trailing set-bits in a uint64_t
#define TRAILSET64(x) \
  (__builtin_ctzll(x+1))

#define WORK_BLOCK(info, space, i) (space->blocks + (info->block_size * (i)))

#define MIN(x,y) ((x <= y) ? (x) : (y))
#define MAX(x,y) ((x >= y) ? (x) : (y))

// prefixes added to hash inputs for each kind of node, to avoid some kinds of attacks.
static unsigned char LEAF_PREFIX = 0x00;
static unsigned char INTERNAL_PREFIX = 0x01;

static inline uint32_t hashes_needed(const store_info_t *info) {
  if (info->nblocks <= 16)
    return 8;
  else {
    // TODO maybe too pessimistic here?
    return 3 * BITLEN64(info->nblocks - 1) + 2;
  }
}

void init_work_space(const store_info_t *info, work_space_t *space) {
  if (!(space->ctx = EVP_MD_CTX_new()))
    EMSG("MD_CTX_new");
  space->nhash = hashes_needed(info);
  if (! (space->hash_ind = malloc(space->nhash * sizeof *space->hash_ind)))
    EMSG("malloc");
  if (! (space->hashes = malloc(space->nhash * sizeof *space->hashes)))
    EMSG("malloc");
  space->nblock = 2;
  if (! (space->blocks = malloc(space->nblock * info->block_size)))
    EMSG("malloc");
}

/* makes sure the work space is large enough for the given info */
void ensure_space(const store_info_t *info, work_space_t *space) {
  uint32_t needed;
  needed = hashes_needed(info);
  if (space->nhash < needed) {
    space->hash_ind = realloc(space->hash_ind, needed * sizeof *space->hash_ind);
    space->hashes = realloc(space->hashes, needed * sizeof *space->hashes);
    space->nhash = needed;
  }
  needed = 2;
  if (space->nblock < needed) {
    space->blocks = realloc(space->blocks, needed * info->block_size);
    space->nblock = needed;
  }
}

void clear_work_space(work_space_t *space) {
  if (space->nblock) {
    free(space->blocks);
  }
  if (space->nhash) {
    free(space->hash_ind);
    free(space->hashes);
  }
  EVP_MD_CTX_free(space->ctx);
}

/* sets info->signature */
void update_signature(store_info_t *info, EVP_MD_CTX *ctx) {
  uint32_t temp32;
  uint64_t temp64;

  if (!EVP_DigestInit(ctx, info->md_alg))
    EMSG("DigestInit");

  temp32 = htole32(info->block_size);
  if (!EVP_DigestUpdate(ctx, &temp32, sizeof temp32))
    EMSG("DigestUpdate");

  temp32 = htole32(info->hash_nid);
  if (!EVP_DigestUpdate(ctx, &temp32, sizeof temp32))
    EMSG("DigestUpdate");

  temp64 = htole64(info->size);
  if (!EVP_DigestUpdate(ctx, &temp64, sizeof temp64))
    EMSG("DigestUpdate");

  if (!EVP_DigestUpdate(ctx, info->root, info->hash_size))
    EMSG("DigestUpdate");

  if (!EVP_DigestFinal_ex(ctx, info->signature, NULL))
    EMSG("DigestFinal");
}

/* assumes block_size, hash_nid, and size are set already.
 * sets all other fields except root and signature. */
void store_info_fillin(store_info_t *info) {
  if (! (info->md_alg = EVP_get_digestbynid(info->hash_nid)))
    EMSG("get_digestbynid");
  info->hash_size = EVP_MD_size(info->md_alg);
  info->nblocks = (info->size - 1) / info->block_size + 1;
  memset(info->root, 0, info->hash_size);
  memset(info->signature, 0, info->hash_size);
}

/* assumes info->size is set, and sets all other fields except the root and signature. */
void store_info_default(store_info_t *info) {
  info->block_size = (1U << 12);
  info->hash_nid = EVP_MD_type(EVP_sha512_224());
  store_info_fillin(info);
}

/* stores the data in store_info_t *info to the FILE *out.
 * If include_root is zero, then the root hash is not written.
 * A count of the total number of bytes written is returned.
 */
int store_info_store(FILE *out, bool include_root, const store_info_t *info) {
  uint32_t temp32;
  uint64_t temp64;
  int count = 0;

  temp32 = htole32(info->block_size);
  if (fwrite(&temp32, sizeof temp32, 1, out) != 1)
    EMSG("store_info_store fwrite");
  count += sizeof temp32;

  temp32 = htole32(info->hash_nid);
  if (fwrite(&temp32, sizeof temp32, 1, out) != 1)
    EMSG("store_info_store fwrite");
  count += sizeof temp32;

  temp64 = htole64(info->size);
  if (fwrite(&temp64, sizeof temp64, 1, out) != 1)
    EMSG("store_info_store fwrite");
  count += sizeof temp64;

  if (include_root) {
    if (fwrite(info->root, info->hash_size, 1, out) != 1)
      EMSG("store_info_store fwrite");
    count += info->hash_size;
  }

  return count;
}

/* loads the data in store_info_t *info from the FILE *in.
 * If include_root is zero, then the root hash is not read.
 * A count of the total number of bytes read is returned.
 */
int store_info_load(FILE *in, bool include_root, store_info_t *info) {
  int count = 0;

  if (fread(&info->block_size, sizeof(uint32_t), 1, in) != 1)
    EMSG("store_info_load fread");
  info->block_size = le32toh(info->block_size);
  count += sizeof(uint32_t);

  if (fread(&info->hash_nid, sizeof(uint32_t), 1, in) != 1)
    EMSG("store_info_load fread");
  info->hash_nid = le32toh(info->hash_nid);
  count += sizeof(uint32_t);

  if (fread(&info->size, sizeof(uint64_t), 1, in) != 1)
    EMSG("store_info_load fread");
  info->size = le32toh(info->size);
  count += sizeof(uint64_t);

  store_info_fillin(info);

  if (include_root) {
    if (fread(info->root, 1, info->hash_size, in) != info->hash_size)
      EMSG("store_info_load fread");
    count += info->hash_size;
  }

  return count;
}


void print_hash(const char *before, const digest_t hash, const char *after,
    FILE *out, const store_info_t *info)
{
  uint32_t i;
  if (before && fputs(before, out) < 0)
    EMSG("hash print");
  for (i=0; i < info->hash_size; ++i) {
    if (fprintf(out, "%02x", hash[i]) <= 0)
      EMSG("hash print");
  }
  if (after && fputs(after, out) < 0)
    EMSG("hash print");
}

void hash_leaf(digest_t dest, const char *restrict block, uint32_t bsize,
    const store_info_t *info, EVP_MD_CTX *ctx)
{
  if (!EVP_DigestInit(ctx, info->md_alg))
    EMSG("DigestInit");
  if (!EVP_DigestUpdate(ctx, &LEAF_PREFIX, sizeof LEAF_PREFIX))
    EMSG("DigestUpdate leaf prefix");
  if (!EVP_DigestUpdate(ctx, block, bsize))
    EMSG("DigestUpdate leaf block");
  if (!EVP_DigestFinal_ex(ctx, dest, NULL))
    EMSG("DigestFinal leaf");
}

void hash_internal(digest_t dest, const digest_t child1, const digest_t child2,
    const store_info_t *info, EVP_MD_CTX *ctx)
{
  if (!EVP_DigestInit(ctx, info->md_alg))
    EMSG("DigestInit");
  if (!EVP_DigestUpdate(ctx, &INTERNAL_PREFIX, sizeof INTERNAL_PREFIX))
    EMSG("DigestUpdate internal prefix");
  if (!EVP_DigestUpdate(ctx, child1, info->hash_size))
    EMSG("DigestUpdate internal left");
  if (!EVP_DigestUpdate(ctx, child2, info->hash_size))
    EMSG("DigestUpdate internal right");
  if (!EVP_DigestFinal_ex(ctx, dest, NULL))
    EMSG("DigestFinal internal");
}

/* sets root and also updates signature; assumes all other parameters are set
 * INCLUDING info->size which must match the data available on FILE *in.
 * If FILE *out is non-NULL, the tree of hashes is written there.
 */
void init_root(FILE *in, FILE *out, store_info_t *info, work_space_t *space) {
  int slen = 0;
  uint64_t remaining_blocks = info->nblocks;;
  size_t count;

  /* write metadata block */
  if (out) {
    count = store_info_store(out, 0, info);
    if (count > info->hash_size)
      EMSG("Not enough room for metadata block");
    while (count < info->hash_size) {
      if (putc(0, out) != 0)
        EMSG("writing nulls at the end of metadata block");
      ++count;
    }
  }

  if (info->size == 0) {
    memset(info->root, 0, info->hash_size);
    return;
  }

  while (remaining_blocks) {
    uint64_t i, pow2 = 1ull << (BITLEN64(remaining_blocks) - 1);
    int j;

    for (i=0; i < pow2; ++i) {
      /* read in next block and hash it */
      if (i + 1 < remaining_blocks || info->size % info->block_size == 0)
        count = info->block_size;
      else
        count = info->size % info->block_size;
      if (fread(space->blocks, count, 1, in) != 1)
        EMSG("fread in init_root");
      ++slen;
      hash_leaf(space->hashes[slen-1], space->blocks, count, info, space->ctx);
      if (out && fwrite(space->hashes[slen-1], 1, info->hash_size, out) != info->hash_size)
        EMSG("fwrite in init_root");

      for (j=0; j < TRAILSET64(i); ++j) {
        /* combine top two items of stack */
        hash_internal(space->hashes[slen-2], space->hashes[slen-2], space->hashes[slen-1], info, space->ctx);
        --slen;
        if (out && fwrite(space->hashes[slen-1], 1, info->hash_size, out) != info->hash_size)
          EMSG("fwrite in init_root");
      }
    }

    remaining_blocks -= pow2;
  }

  while (slen >= 2) {
    /* combine top two items of stack */
    hash_internal(space->hashes[slen-2], space->hashes[slen-2], space->hashes[slen-1], info, space->ctx);
    --slen;
    if (out && fwrite(space->hashes[slen-1], 1, info->hash_size, out) != info->hash_size)
      EMSG("fwrite in init_root");
  }

  memcpy(info->root, space->hashes[0], info->hash_size);
  update_signature(info, space->ctx);
}

/* Helper function for pre_read which gets the hash indices needed to verify
 * the specified range of blocks.
 */
uint32_t hash_indices_for_range(
    uint64_t nblocks, uint64_t block_offset, uint64_t block_count,
    uint64_t index_offset, uint64_t *indices, uint32_t next_ind)
{
  uint64_t pow2, left_blocks;

  if (block_count == 0) {
    indices[next_ind] = index_offset + 2*nblocks - 2;
    return next_ind + 1;
  }

  if (nblocks == 1)
    return next_ind;

  pow2 = ((uint64_t)1) << (BITLEN64(nblocks - 1) - 1);

  left_blocks = MIN(block_count, pow2 - MIN(pow2, block_offset));
  next_ind = hash_indices_for_range(pow2, block_offset, left_blocks, index_offset, indices, next_ind);
  return hash_indices_for_range(nblocks - pow2, block_offset + left_blocks - pow2, block_count - left_blocks,
      index_offset + 2*pow2 - 1, indices, next_ind);
}

/* Fills in rreq in order to read count bytes at the given offset into buf. */
void pre_read(read_req_t *rreq, char *buf, uint32_t count, uint64_t offset,
    const store_info_t *info, work_space_t *space)
{
  if (offset + count > info->size)
    EMSG("pre_read request off the end of the data");

  rreq->buf = buf;
  rreq->count = count;
  rreq->offset = offset;

  rreq->block_offset = rreq->offset / info->block_size;

  if (rreq->count == 0) {
    rreq->nhash = 0;
    rreq->block_count = 0;
    return;
  }

  rreq->block_count = (rreq->offset + rreq->count - 1) / info->block_size + 1 - rreq->block_offset;

  assert (rreq->block_count > 0);

  /* Here we figure out how to assign memory for the blocks.
   * The last_block is always used, and it may be from the end of buf or (more likely)
   * come from the extra work space. The last_block is the only one which might be incomplete.
   * The first_block_is used whenever block_count is at least 2, and it also may come from
   * the beginning of buf or (more likely) from the extra space.
   * The middle_blocks, when needed, are always from the middle of the buf array.
   */

  // first block - use *second* block from space, or buf
  if (rreq->block_count >= 2) {
    if (rreq->offset % info->block_size)
      rreq->first_block = space->blocks + info->block_size;
    else
      rreq->first_block = rreq->buf;
  }

  // middle blocks - use buf
  if (rreq->block_count >= 3)
    rreq->middle_blocks = rreq->buf + info->block_size - (rreq->offset % info->block_size);

  // last block - use *first* block from space, or buf
  if (rreq->block_offset + rreq->block_count >= info->nblocks && info->size % info->block_size) {
    // request goes to the last block, and the last block of data is only partial
    rreq->lbsize = info->size % info->block_size;
    if (rreq->offset + rreq->count == info->size && rreq->count >= rreq->lbsize)
      rreq->last_block = rreq->buf + rreq->count - rreq->lbsize;
    else
      rreq->last_block = space->blocks;
  }
  else {
    // the last block of the request will be full
    rreq->lbsize = info->block_size;
    if ((rreq->offset + rreq->count) % info->block_size || rreq->count < rreq->lbsize)
      rreq->last_block = space->blocks;
    else
      rreq->last_block = rreq->buf + rreq->count - info->block_size;
  }

  // fill in hash indices for the request
  rreq->hash_ind = space->hash_ind;
  rreq->hashes = space->hashes;

  rreq->nhash = hash_indices_for_range(info->nblocks, rreq->block_offset, rreq->block_count, 0, rreq->hash_ind, 0);
  assert (rreq->nhash <= space->nhash);
}

/* Helper function for post_read which uses the read result to re-compute the root hash.
 * A pointer to the computed root hash is returned.
 */
const digest_t * compute_hash_range(
    uint64_t nblocks, uint64_t block_offset, uint64_t block_count,
    const read_req_t *rreq, uint64_t rblock_off, const digest_t **hashes, digest_t *space,
    const store_info_t *info, EVP_MD_CTX *ctx)
{
  uint64_t pow2, left_blocks;
  const digest_t *left, *right;

  assert (nblocks > 0);

  // base case: use the hash given in request when this sub-problem
  // doesn't overlap with the fetched data.
  if (block_count == 0) {
    return (*hashes)++;
  }

  // base case: a single data item means it's a single leaf node, and we
  // just compute its hash.
  if (nblocks == 1) {
    if (rblock_off == rreq->block_count - 1)
      hash_leaf(*space, rreq->last_block, rreq->lbsize, info, ctx);
    else if (rblock_off == 0)
      hash_leaf(*space, rreq->first_block, info->block_size, info, ctx);
    else
      hash_leaf(*space, rreq->middle_blocks + (rblock_off - 1) * info->block_size, info->block_size, info, ctx);
    return space;
  }

  // pow2 is the largest power of 2 strictly less than nblocks.
  pow2 = ((uint64_t)1) << (BITLEN64(nblocks - 1) - 1);

  // make the two recursive calls
  left_blocks = MIN(block_count, pow2 - MIN(pow2, block_offset));
  left = compute_hash_range(pow2, block_offset, left_blocks,
      rreq, rblock_off, hashes, space, info, ctx);
  right = compute_hash_range(nblocks - pow2, block_offset + left_blocks - pow2, block_count - left_blocks,
      rreq, rblock_off + left_blocks, hashes, space + 1,
      info, ctx);

  hash_internal(*space, *left, *right, info, ctx);
  return space;
}

/* copy data back to the buffer and check the hashes.
 * Returns true iff the hashes match.
 */
bool post_read(read_req_t *rreq, const store_info_t *info, work_space_t *space)
{
  uint32_t off, len;
  const digest_t *res, *dspace;

  if (rreq->count == 0) return true;

  // copy first block contents to buf, if needed
  if (rreq->block_count >= 2 && rreq->first_block == space->blocks + info->block_size) {
    off = rreq->offset % info->block_size;
    memcpy(rreq->buf, rreq->first_block + off, info->block_size - off);
  }

  // copy last block contents to buf, if needed
  if (rreq->last_block == space->blocks) {
    if (rreq->block_count == 1)
      off = rreq->offset % info->block_size;
    else
      off = 0;
    len = (rreq->offset + rreq->count - 1) % info->block_size + 1 - off;
    memcpy(rreq->buf + rreq->count - len, rreq->last_block + off, len);
  }

  // compute new root hash
  dspace = rreq->hashes;
  res = compute_hash_range(info->nblocks, rreq->block_offset, rreq->block_count,
      rreq, 0, &dspace, space->hashes + rreq->nhash, info, space->ctx);

  // compare computed and stored root hash to check integrity
  return memcmp(res, info->root, info->hash_size) == 0;
}
