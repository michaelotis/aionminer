#pragma once
// Equihash solver
// Copyright (c) 2016-2016 John Tromp


#include "../blake2/blake2.h"
#ifdef __APPLE__
#include "osx_barrier.h"
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#else
#include <boost/endian/endian.hpp>
#include "pthreads/pthread.h"
#endif
#include <stdint.h> // for types uint32_t,uint64_t
#include <string.h> // for functions memset
#include <stdlib.h> // for function qsort

#define htole32(x) (x);
typedef uint32_t u32;
typedef unsigned char uchar;

// algorithm parameters, prefixed with W to reduce include file conflicts

#ifndef WN
#define WN	210
#endif

#ifndef WK
#define WK	9
#endif

#define PARAMETER_N WN
#define PARAMETER_K WK

#define NDIGITS		(WK+1)
#define DIGITBITS	(WN/(NDIGITS))

#define PROOFSIZE (1<<WK)
#define BASE (1<<DIGITBITS)
#define NHASHES (2*BASE)
#define HASHESPERBLAKE (512/WN)
#define HASHLEN (WN+7)/8
#define HASHOUT (HASHESPERBLAKE*HASHLEN)
#define HEADERNONCELEN 140


typedef u32 proof[PROOFSIZE];

void setheader(blake2b_state *ctx, const char *header, const u32 headerLen, const char* nce, const u32 nonceLen) {
	uint32_t le_N = WN;
	uint32_t le_K = WK;
	uchar personal[] = "AION0PoW01230123";
	memcpy(personal + 8, &le_N, 4);
	memcpy(personal + 12, &le_K, 4);
	blake2b_param P[1];
	P->digest_length = HASHOUT;
	P->key_length = 0;
	P->fanout = 1;
	P->depth = 1;
	P->leaf_length = 0;
	P->node_offset = 0;
	P->node_depth = 0;
	P->inner_length = 0;
	memset(P->reserved, 0, sizeof(P->reserved));
	memset(P->salt, 0, sizeof(P->salt));
	memcpy(P->personal, (const uint8_t *)personal, 16);
	blake2b_init_param(ctx, P);
	blake2b_update(ctx, (const uchar *)header, headerLen);
	blake2b_update(ctx, (const uchar *)nce, nonceLen);

	// Print personalization
	// for(int i = 0; i < 16; i++){
	//   if(i > 0 && i % 8 == 0){
	//     printf("\n");
	//   }
	//   printf("%.2x, ", personal[i]);
	// }
	// printf("\n\n");

	// // Print header
	// printf("Header len: %d\n", headerLen);
	// for(int i = 0; i < headerLen; i++){
	//   if(i > 0 && i % 8 == 0){
	//     printf("\n");
	//   }
	//   printf("%.2x, ", ((const uchar *)header)[i]);
	// }
	// printf("\n\n");

	// //Print nonce
	// for(int i = 0; i < nonceLen; i++){
	//   if(i > 0 && i % 8 == 0){
	//     printf("\n");
	//   }
	//   printf("%.2x, ", ((const uchar *)nce)[i]);
	// }
	// printf("\n\n");
}

enum verify_code { POW_OK, POW_HEADER_LENGTH, POW_DUPLICATE, POW_OUT_OF_ORDER, POW_NONZERO_XOR };
const char *errstr[] = { "OK", "wrong header length", "duplicate index", "indices out of order", "nonzero xor" };

void genhash(const blake2b_state *ctx, u32 idx, uchar *hash) {
	blake2b_state state = *ctx;
	u32 leb = htole32(idx / HASHESPERBLAKE);
	blake2b_update(&state, (uchar *)&leb, sizeof(u32));
	uchar blakehash[HASHOUT];
	blake2b_final(&state, blakehash, HASHOUT);
	memcpy(hash, blakehash + (idx % HASHESPERBLAKE) * WN / 8, WN / 8);
}

int verifyrec(const blake2b_state *ctx, u32 *indices, uchar *hash, int r) {
	if (r == 0) {
		genhash(ctx, *indices, hash);
		return POW_OK;
	}
	u32 *indices1 = indices + (1 << (r - 1));
	if (*indices >= *indices1)
		return POW_OUT_OF_ORDER;
	uchar hash0[WN / 8], hash1[WN / 8];
	int vrf0 = verifyrec(ctx, indices, hash0, r - 1);
	if (vrf0 != POW_OK)
		return vrf0;
	int vrf1 = verifyrec(ctx, indices1, hash1, r - 1);
	if (vrf1 != POW_OK)
		return vrf1;
	for (int i = 0; i < WN / 8; i++)
		hash[i] = hash0[i] ^ hash1[i];
	int i, b = r < WK ? r * DIGITBITS : WN;
	for (i = 0; i < b / 8; i++)
		if (hash[i])
			return POW_NONZERO_XOR;
	if ((b % 8) && hash[i] >> (8 - (b % 8)))
		return POW_NONZERO_XOR;
	return POW_OK;
}

int compu32(const void *pa, const void *pb) {
	u32 a = *(u32 *)pa, b = *(u32 *)pb;
	return a<b ? -1 : a == b ? 0 : +1;
}

bool duped(proof prf) {
	proof sortprf;
	memcpy(sortprf, prf, sizeof(proof));
	qsort(sortprf, PROOFSIZE, sizeof(u32), &compu32);
	for (u32 i = 1; i<PROOFSIZE; i++)
		if (sortprf[i] <= sortprf[i - 1])
			return true;
	return false;
}

// verify Wagner conditions
int verify(u32 indices[PROOFSIZE], const char *headernonce, const u32 headerlen) {
	if (headerlen != HEADERNONCELEN)
		return POW_HEADER_LENGTH;
	if (duped(indices))
		return POW_DUPLICATE;
	blake2b_state ctx;
	setheader(&ctx, headernonce, HEADERNONCELEN);
	uchar hash[WN / 8];
	return verifyrec(&ctx, indices, hash, WK);
}