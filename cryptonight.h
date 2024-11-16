#ifndef __CRYPTONIGHT_H_INCLUDED
#define __CRYPTONIGHT_H_INCLUDED

#include <stddef.h>
#include "crypto/oaes_lib.h"
#include "miner.h"

// Definições de constantes para memória e tamanho de blocos
#define MEMORY             (1 << 21)   // 2 MiB
#define ITER               (1 << 20)
#define AES_BLOCK_SIZE     16
#define AES_KEY_SIZE       32  // Tamanho da chave AES (32 bytes)
#define INIT_SIZE_BLK      8
#define INIT_SIZE_BYTE     (INIT_SIZE_BLK * AES_BLOCK_SIZE)  // 128 bytes

// Definição de estrutura de estado de hash, alinhada para otimização
#pragma pack(push, 1)
union hash_state {
    uint8_t b[200];        // Representação em bytes do estado
    uint64_t w[25];        // Representação em palavras de 64 bits
};
#pragma pack(pop)

// Definição de estrutura de estado para o slow hash do CryptoNight
#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;  // Estado do hash (pode ser usado diretamente)
    struct {
        uint8_t k[64];     // Chave de 64 bytes
        uint8_t init[INIT_SIZE_BYTE];  // Dados de inicialização (128 bytes)
    };
};
#pragma pack(pop)

// Definição da estrutura de contexto para CryptoNight, dependendo da implementação do AES
#ifdef USE_LOBOTOMIZED_AES
struct cryptonight_ctx {
    uint8_t long_state[MEMORY] __attribute__((aligned(16)));   // Estado longo (memória de 2 MiB)
    union cn_slow_hash_state state;                             // Estado do hash
    uint8_t text[INIT_SIZE_BYTE] __attribute__((aligned(16)));  // Texto para manipulação do hash
    uint8_t a[AES_BLOCK_SIZE] __attribute__((aligned(16)));     // Bloco AES "a"
    uint8_t b[AES_BLOCK_SIZE] __attribute__((aligned(16)));     // Bloco AES "b"
    uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));     // Bloco AES "c"
    oaes_ctx* aes_ctx;                                          // Contexto AES (usado para chave AES)
};

#else
struct cryptonight_ctx {
    uint8_t long_state[MEMORY] __attribute__((aligned(16)));   // Estado longo (memória de 2 MiB)
    union cn_slow_hash_state state;                             // Estado do hash
    uint8_t text[INIT_SIZE_BYTE] __attribute__((aligned(16)));  // Texto para manipulação do hash
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));  // Bloco "a" (64-bit)
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));  // Bloco "b" (64-bit)
    uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));     // Bloco AES "c"
    oaes_ctx* aes_ctx;                                          // Contexto AES
};
#endif

// Declaração das funções de hash (Blake2, Groestl, JH, Skein)
void do_blake_hash(const void* input, size_t len, char* output);
void do_groestl_hash(const void* input, size_t len, char* output);
void do_jh_hash(const void* input, size_t len, char* output);
void do_skein_hash(const void* input, size_t len, char* output);

// Função para realizar a operação XOR em blocos de dados
void xor_blocks_dst(const uint8_t *restrict a, const uint8_t *restrict b, uint8_t *restrict dst);

// Função principal do CryptoNight, que executa o hash baseado no contexto
void cryptonight_hash_ctx(void* output, const void* input, struct cryptonight_ctx* ctx);

// Funções relacionadas ao Keccak (parte do processo de hashing)
void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
void keccakf(uint64_t st[25], int rounds);

// Função extra de hash para uso adicional no processo de hashing
extern void (* const extra_hashes[4])(const void *, size_t, char *);

#endif
