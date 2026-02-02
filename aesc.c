#include <stdio.h>
#include <stdint.h>
#include <wmmintrin.h>
#include <x86intrin.h>
#include <string.h>

// --- Print 16-byte buffer in hex ---
/*void print_hex(uint8_t *buf, int len) {
    for (int i = 0; i < len; i++)
        printf("%02X ", buf[i]);
    printf("\n");
}*/

#define AES128_KEY_EXPAND_STEP(prev, next, RCON) do { \
    __m128i tmp1 = (prev); \
    __m128i tmp2 = _mm_aeskeygenassist_si128(tmp1, RCON); \
    tmp2 = _mm_shuffle_epi32(tmp2, _MM_SHUFFLE(3,3,3,3)); \
    tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4)); \
    tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4)); \
    tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4)); \
    (next) = _mm_xor_si128(tmp1, tmp2); \
} while(0)

void aes128_key_expansion(uint8_t *key, __m128i roundkeys[11]) {
    roundkeys[0] = _mm_loadu_si128((__m128i*)key);
    AES128_KEY_EXPAND_STEP(roundkeys[0], roundkeys[1], 0x01);
    AES128_KEY_EXPAND_STEP(roundkeys[1], roundkeys[2], 0x02);
    AES128_KEY_EXPAND_STEP(roundkeys[2], roundkeys[3], 0x04);
    AES128_KEY_EXPAND_STEP(roundkeys[3], roundkeys[4], 0x08);
    AES128_KEY_EXPAND_STEP(roundkeys[4], roundkeys[5], 0x10);
    AES128_KEY_EXPAND_STEP(roundkeys[5], roundkeys[6], 0x20);
    AES128_KEY_EXPAND_STEP(roundkeys[6], roundkeys[7], 0x40);
    AES128_KEY_EXPAND_STEP(roundkeys[7], roundkeys[8], 0x80);
    AES128_KEY_EXPAND_STEP(roundkeys[8], roundkeys[9], 0x1B);
    AES128_KEY_EXPAND_STEP(roundkeys[9], roundkeys[10], 0x36);
}

void aes128_encrypt_block(uint8_t *in, uint8_t *out, __m128i roundkeys[11]) {
    __m128i block = _mm_loadu_si128((__m128i*)in);
    block = _mm_xor_si128(block, roundkeys[0]);
    for (int i = 1; i < 10; i++)
        block = _mm_aesenc_si128(block, roundkeys[i]);
    block = _mm_aesenclast_si128(block, roundkeys[10]);
    _mm_storeu_si128((__m128i*)out, block);
}

void aes128_decrypt_block(uint8_t *in, uint8_t *out, __m128i roundkeys[11]) {
    __m128i dec_keys[11];
    dec_keys[0] = roundkeys[10];
    for (int i = 1; i < 10; i++)
        dec_keys[i] = _mm_aesimc_si128(roundkeys[10-i]);
    dec_keys[10] = roundkeys[0];

    __m128i block = _mm_loadu_si128((__m128i*)in);
    block = _mm_xor_si128(block, dec_keys[0]);
    for (int i = 1; i < 10; i++)
        block = _mm_aesdec_si128(block, dec_keys[i]);
    block = _mm_aesdeclast_si128(block, dec_keys[10]);
    _mm_storeu_si128((__m128i*)out, block);
}

int main() {
    uint8_t plaintext[256] = "abcabcabcabcabcd";
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16+1];
    decrypted[16] = 0; // null terminator

    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                               0xab,0xf7,0x97,0x75,0x46,0x7a,0x03,0x55};


    	__m128i roundkeys[11];

	 aes128_key_expansion(key, roundkeys);
    uint64_t start=0,end=0;

asm volatile(
    "lfence\n\t"
    "rdtsc\n\t"
    "shl $32, %%rdx\n\t"
    "or %%rdx, %%rax"
    : "=a"(start)
    :
    : "%rdx"
);

aes128_encrypt_block(plaintext, ciphertext, roundkeys);
aes128_decrypt_block(ciphertext, decrypted, roundkeys);

asm volatile(
    "rdtsc\n\t"
    "shl $32, %%rdx\n\t"
    "or %%rdx, %%rax"
    : "=a"(end)
    :
    : "%rcx", "%rdx"
);

uint64_t cycles = end - start;
printf("%lu\n", cycles);  
    return 0;

    }


