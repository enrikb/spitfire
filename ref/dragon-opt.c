/**
 * @file dragon-ref.c
 * Implementation of Dragon
 * This source is provided without warranty
 * or guarantee of any kind. Use at your own risk.
 * @author Information Security Institute
 */
#include <assert.h>

#include "ecrypt-sync.h"
#include "dragon-sboxes.c"

/**
 * The DRAGON_OFFSET macro calculates the position of the 
 * ith_element within the circular buffer that represents the
 * NLFSR.
 */
#define DRAGON_OFFSET(ctx, ith_element, state_size) \
    ((ctx->nlfsr_offset + ith_element) & state_size)

/**
 * The DRAGON_NLFSR_WORD macro retrieves the ith 32-bit word
 * from the Dragon NLFSR.
 */
#define DRAGON_NLFSR_WORD(ctx, ith_word) \
    *(ctx->nlfsr_word + DRAGON_OFFSET(ctx, ith_word, (DRAGON_NLFSR_SIZE - 1)))

#define DRAGON_UPDATE(a, b, c, d, e, f) \
    b ^= a; d ^=c; f ^= e; \
    c += b; e +=d; a += f; \
    f ^= G2(c); b ^= G3(e); d ^= G1(a); \
    e ^= H3(f); a ^= H1(b); c ^= H2(d); \
    b += e; d += a; f += c;\
    c ^= b; e ^= d; a ^= f;\
    
/*
 * Key and message independent initialization. This function will be
 * called once when the program starts (e.g., to build expanded S-box
 * tables).
 */
void ECRYPT_init(void)
{
}

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void ECRYPT_keysetup(
    ECRYPT_ctx*  ctx,
    const u8*    key,
    u32          keysize, /* Key size in bits. */
    u32          ivsize)  /* IV size in bits. */
{
    u32   idx;
    u32   key_word;

    assert(ctx && key);

    ctx->nlfsr_offset  = 0;
    ctx->key_size      = keysize;
    ctx->full_rekeying = 1;
    ctx->buffer_index  = 0;
 
    /**
      * Dragon supports the following combinations of key and IV sizes only:
      * (128, 128) and (256, 256) bits. Mix and matching is not supported,
      * nor are other sizes. The ivsize parameter is ignored here.
      */
    if (keysize == 128) 
    {
        /* For a keysize of 128 bits, the Dragon NLFSR is initialized 
           using K and IV as follows (where k' and iv' represent 
           swapping of halves of key and iv respectively):
           k | k' ^ iv' | iv | (k ^ iv') | k' | (k ^ iv) | iv' | (k' ^ iv)           
         */
        for (idx = 0; idx < 4; idx++) {
            key_word = U8TO32_LITTLE(key + idx * 4);
            
            ctx->nlfsr_word[0+idx]  = ctx->nlfsr_word[12+idx] = 
                ctx->nlfsr_word[20+idx] = key_word;
        }
                
        /* then write k' */
        for (idx = 0; idx < 2; idx++) {
            key_word = U8TO32_LITTLE(key + 8 + idx * 4 );
            ctx->nlfsr_word[4+idx] = ctx->nlfsr_word[16+idx] = 
                ctx->nlfsr_word[28+idx] = key_word;

            key_word = U8TO32_LITTLE(key + idx * 4);
            ctx->nlfsr_word[6+idx] = ctx->nlfsr_word[18+idx] = 
                ctx->nlfsr_word[30+idx] = key_word;
        }
    }
    else 
    {
        /* For a keysize of 256 bits, the Dragon NLFSR is initialized 
           using K and IV as follows (where {k} and {iv} represent 
           the bitwise complements of keys and ivs repsectively:
           k | k ^ iv | {k ^ iv} | iv
         */
        for (idx = 0; idx < 8; idx++) {
            key_word = U8TO32_LITTLE(key + idx * 4);

            ctx->nlfsr_word[0+idx]  = ctx->nlfsr_word[8+idx] = key_word;
            ctx->nlfsr_word[16+idx] = key_word;
        }
    }

    /* Preserve the state for the key-IV-IV-... scenario described below
     */
    for (idx = 0; idx < DRAGON_NLFSR_SIZE; idx++) {
        ctx->init_state[idx] = ctx->nlfsr_word[idx];
    }
}

#define DRAGON_MIXING_STAGES   16 /* number of mixes during initialization */

/*
 * IV setup. After having called ECRYPT_keysetup(), the user is
 * allowed to call ECRYPT_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void ECRYPT_ivsetup(
    ECRYPT_ctx* ctx,
    const u8* iv)
{
    u32 a, b, c, d;
    u32 e = 0x00004472;
    u32 f = 0x61676F6E;
    u32 iv_word;
    u32 idx;
    
    assert(ctx && iv);

    /**
      * This is either a continuation of key initialization,
      * or a fresh IV rekeying. In the latter case, restore the
      * state to the post-keysetup state.
      */
    if (ctx->full_rekeying == 0) {
        for (idx = 0; idx < DRAGON_NLFSR_SIZE; idx++) {
            ctx->nlfsr_word[idx] = ctx->init_state[idx];
        }
    }

    /* For a keysize of 128 bits, the Dragon NLFSR is initialized 
       using K and IV as follows (where k' and iv' represent 
       swapping of halves of key and iv respectively):
       k | k' ^ iv' | iv | k ^ iv' | k' | k ^ iv | iv' | k' ^ iv

       Therefore initialization of locations {0, 1, 8, 9} are 
       deliberately omitted here, as the iv is not involved.
    */
    if (ctx->key_size == 128) 
    {
        /* write iv first */
        for (idx = 0; idx < 4; idx++) {
            iv_word = U8TO32_LITTLE(iv + idx * 4);

            ctx->nlfsr_word[8+idx]   = iv_word;
            ctx->nlfsr_word[20+idx] ^= iv_word;
            ctx->nlfsr_word[28+idx] ^= iv_word;
        }

        /* then iv' */
        for (idx = 0; idx < 2; idx++) {
            iv_word = U8TO32_LITTLE(iv + 8 + idx * 4);

            ctx->nlfsr_word[ 4+idx] ^= iv_word;
            ctx->nlfsr_word[12+idx] ^= iv_word;
            ctx->nlfsr_word[24+idx]  = iv_word;

            iv_word = U8TO32_LITTLE(iv + idx * 4);

            ctx->nlfsr_word[ 6+idx] ^= iv_word;
            ctx->nlfsr_word[14+idx] ^= iv_word;
            ctx->nlfsr_word[26+idx]  = iv_word;
        }
    }
    else 
    {
        /* For a keysize of 256 bits, the Dragon NLFSR is initialized 
           using K and IV as follows (where {k} and {iv} represent 
           the bitwise complements of keys and ivs repsectively:
           k | (k ^ iv) | {k ^ iv} | iv
         */
        for (idx = 0; idx < 8; idx++) {
            iv_word = U8TO32_LITTLE(iv + idx * 4);

            ctx->nlfsr_word[ 8 + idx] ^= iv_word;
            ctx->nlfsr_word[16 + idx] ^= (iv_word ^ 0xFFFFFFFF);
            ctx->nlfsr_word[24 + idx]  = iv_word;
        }
    }
    
    /** Iterate mixing process */
    for (idx = 0; idx < DRAGON_MIXING_STAGES; idx++) {
        a = DRAGON_NLFSR_WORD(ctx, 0)  ^ 
            DRAGON_NLFSR_WORD(ctx, 24) ^
            DRAGON_NLFSR_WORD(ctx, 28);

        b = DRAGON_NLFSR_WORD(ctx, 1)  ^
            DRAGON_NLFSR_WORD(ctx, 25) ^
            DRAGON_NLFSR_WORD(ctx, 29);

        c = DRAGON_NLFSR_WORD(ctx, 2)  ^
            DRAGON_NLFSR_WORD(ctx, 26) ^
            DRAGON_NLFSR_WORD(ctx, 30);

        d = DRAGON_NLFSR_WORD(ctx, 3)  ^
            DRAGON_NLFSR_WORD(ctx, 27) ^
            DRAGON_NLFSR_WORD(ctx, 31);

        DRAGON_UPDATE(a, b, c, d, e, f); 
     
         ctx->nlfsr_offset += (DRAGON_NLFSR_SIZE - 4); 

        DRAGON_NLFSR_WORD(ctx, 0) = a ^ DRAGON_NLFSR_WORD(ctx, 20);
        DRAGON_NLFSR_WORD(ctx, 1) = b ^ DRAGON_NLFSR_WORD(ctx, 21);
        DRAGON_NLFSR_WORD(ctx, 2) = c ^ DRAGON_NLFSR_WORD(ctx, 22);
        DRAGON_NLFSR_WORD(ctx, 3) = d ^ DRAGON_NLFSR_WORD(ctx, 23);
    }
    ctx->state_counter[0] = e;
    ctx->state_counter[1] = f;

    /* Assume that the next keying operation will be IV only */
    ctx->full_rekeying = 0 ;
}

/**
 * DRAGON_ROUND produces one block of keystream
 */
#define BASIC_RND(ctx, a, loc_a, b, loc_b, c, loc_c, \
                         d, loc_d, e, loc_e, f, loc_fb1, c1, c2)\
    a = ctx->nlfsr_word[loc_a]; \
    c = ctx->nlfsr_word[loc_c]; \
    e = ctx->nlfsr_word[loc_e] ^ c1; \
    b = ctx->nlfsr_word[loc_b] ^ a; \
    d = ctx->nlfsr_word[loc_d] ^ c; \
    f = (ctx->nlfsr_word[loc_e+1] ^ e) ^ (c2++); \
    c += b; \
    e += d; \
    a += f; \
    f ^= G2(c); b ^= G3(e); d ^= G1(a); \
    e ^= H3(f); a ^= H1(b); c ^= H2(d); \
    ctx->nlfsr_word[loc_fb1] = b + e;  \
    ctx->nlfsr_word[loc_fb1+1] = c ^ (b + e); 

#define KEYSTREAM_RND(ctx, a, loc_a, b, loc_b, c, loc_c, \
                         d, loc_d, e, loc_e, f, loc_fb1, c1, c2, in, out)\
    BASIC_RND(ctx, a, loc_a, b, loc_b, c, loc_c, \
       d, loc_d, e, loc_e, f, loc_fb1, c1, c2) \
    *(out++) = a ^ (f + c); \
    *(out++) = e ^ (d + a);  

#define PROCESS_RND(ctx, a, loc_a, b, loc_b, c, loc_c, \
                         d, loc_d, e, loc_e, f, loc_fb1, c1, c2, in, out)\
    BASIC_RND(ctx, a, loc_a, b, loc_b, c, loc_c, \
       d, loc_d, e, loc_e, f, loc_fb1, c1, c2) \
    *(out++) = *(in++) ^ a ^ (f + c); \
    *(out++) = *(in++) ^ e ^ (d + a);  
 
/** 
 * DRAGON_ROUND produces 16 blocks of keystream
 */
#define DRAGON_16RND(RND, ctx, a, b, c, d, e, f, c1, c2, in, out) \
  RND(ctx, a,  0, b,  9, c, 16, d, 19, e, 30, f, 30, c1, c2, in, out) \
  RND(ctx, a, 30, b,  7, c, 14, d, 17, e, 28, f, 28, c1, c2, in, out) \
  RND(ctx, a, 28, b,  5, c, 12, d, 15, e, 26, f, 26, c1, c2, in, out) \
  RND(ctx, a, 26, b,  3, c, 10, d, 13, e, 24, f, 24, c1, c2, in, out) \
  RND(ctx, a, 24, b,  1, c,  8, d, 11, e, 22, f, 22, c1, c2, in, out) \
  RND(ctx, a, 22, b, 31, c,  6, d,  9, e, 20, f, 20, c1, c2, in, out) \
  RND(ctx, a, 20, b, 29, c,  4, d,  7, e, 18, f, 18, c1, c2, in, out) \
  RND(ctx, a, 18, b, 27, c,  2, d,  5, e, 16, f, 16, c1, c2, in, out) \
  RND(ctx, a, 16, b, 25, c,  0, d,  3, e, 14, f, 14, c1, c2, in, out) \
  RND(ctx, a, 14, b, 23, c, 30, d,  1, e, 12, f, 12, c1, c2, in, out) \
  RND(ctx, a, 12, b, 21, c, 28, d, 31, e, 10, f, 10, c1, c2, in, out) \
  RND(ctx, a, 10, b, 19, c, 26, d, 29, e,  8, f,  8, c1, c2, in, out) \
  RND(ctx, a,  8, b, 17, c, 24, d, 27, e,  6, f,  6, c1, c2, in, out) \
  RND(ctx, a,  6, b, 15, c, 22, d, 25, e,  4, f,  4, c1, c2, in, out) \
  RND(ctx, a,  4, b, 13, c, 20, d, 23, e,  2, f,  2, c1, c2, in, out) \
  RND(ctx, a,  2, b, 11, c, 18, d, 21, e,  0, f,  0, c1, c2, in, out) 

/**
 * Generate #(blocks) 64-bit blocks of keystream. 
 * @param  ctx        [In/Out]  Dragon context
 * @param  keystream  [Out]        pre-allocated array containing 8*(blocks)
 *                                bytes of memory
 * @param  blocks      [In]        number of keystream blocks to produce
 */
void ECRYPT_keystream_blocks(
  ECRYPT_ctx* ctx,
  u8* keystream,
  u32 blocks)
{
    u32 *k_ptr = (u32*)keystream;
    u32 a, b, c, d, e, f;

     u32 c1, c2;

    assert(ctx && keystream);

    c1 = ctx->state_counter[0];
    c2 = ctx->state_counter[1];

    while (blocks > 0) {
        DRAGON_16RND(KEYSTREAM_RND, ctx, a, b, c, d, e, f, c1, c2, k_ptr, k_ptr)
        blocks -= 16;
    }
    if (c2 < ctx->state_counter[1]) {
        ctx->state_counter[0] = c1+1;
    }
    ctx->state_counter[1] = c2;
}

/**
 * Encrypt/Decrypt #(blocks) 64-bit blocks of text
 * @param  action  [In]         This parameter has no meaning for Dragon
 * @param  ctx     [In/Out]  Dragon context
 * @param  input   [In]      (plain/cipher)text blocks for (en/de)crypting
 * @param  output  [Out]     pre-allocated array for (cipher/plain)text blocks
 *                             consisting of 8*(blocks) bytes
 * @param  blocks  [In]         number of blocks to (en/de)crypt
 */
void ECRYPT_process_blocks(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  ECRYPT_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 blocks)
{ 
    u32 *in = (u32*)input;
    u32 *out = (u32*)output;

    u32 a, b, c, d, e, f;
    u32 c1, c2;

    assert(ctx && input && output);

    c1 = ctx->state_counter[0];
    c2 = ctx->state_counter[1];

    while (blocks > 0) {
        DRAGON_16RND(PROCESS_RND, ctx, a, b, c, d, e, f, c1, c2, in, out)
        blocks-=16;
    }
    if (c2 < ctx->state_counter[1]) {
        ctx->state_counter[0] = c1+1;
    }
    ctx->state_counter[1] = c2;
}

/**
 * Generate an arbitrary number of keystream bytes. Note this API 
 * is slower than block-wise encryption as Dragon is a 64-bit 
 * block-oriented  cipher
 *
 * @param  ctx        [In/Out]  Dragon context
 * @param  keystream  [Out]        pre-allocated array containing (msglen)
 *                                bytes
 * @param  length     [In]        number of keystream bytes to produce
 */
void ECRYPT_keystream_bytes(
    ECRYPT_ctx* ctx,
    u8* keystream,
    u32 length)
{
    assert(ctx && keystream);

    while ((length--) > 0) {
        if (ctx->buffer_index == 0) {
            ECRYPT_keystream_blocks(
                ctx, 
                ctx->keystream_buffer, 
                DRAGON_BUFFER_SIZE);
        }
        *(keystream++) = ctx->keystream_buffer[ctx->buffer_index];
        ctx->buffer_index = (ctx->buffer_index % DRAGON_BUFFER_SIZE);
    }
}

/**
 * Encrypt an arbitrary number of bytes. Note this API is slower
 * than block-wise encryption as Dragon is a 64-bit block-oriented 
 * cipher
 *
 * @param  action  [In]      This parameter has no meaning for Dragon
 * @param  ctx     [In/Out]  Dragon context
 * @param  input   [In]         (plain)/(cipher)text for (en/de)crypting
 * @param  output  [Out]     (cipher)/(plain)text for (en/de)crypting
 * @param  msglen  [In]      number of bytes to (en/de)crypt
 */
void ECRYPT_process_bytes(
    int action,                 /* 0 = encrypt; 1 = decrypt; */
    ECRYPT_ctx* ctx,
    const u8* input,
    u8* output,
    u32 msglen)
{
    u32 len = msglen;
    u32 i;

    assert(ctx && input && output);

    ECRYPT_keystream_bytes(ctx, output, len);

    for (i = 0; i < msglen; i++) {
        output[i] ^= input[i];
    }
}

