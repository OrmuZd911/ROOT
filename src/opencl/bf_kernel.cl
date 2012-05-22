/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on Solar Designer implementation of bf_std.c in jtr-v1.7.8 
*/
#define BF_ROUNDS	16

typedef uint BF_word;

typedef uint BF_key[BF_ROUNDS + 2];

struct BF_ctx_S {
	uint S[4][0x100];
};

struct BF_ctx_P{
	uint P[18];
};

#define INDEX				[index]

#define BF_ROUND(ctx_S,ctx_P, L, R, N, tmp1, tmp2, tmp3, tmp4) \
	tmp1 = ((unsigned long)L & 0xff); \
        tmp2 = ((unsigned long)L >> 8); \
	tmp2 = ((unsigned long)tmp2 & 0xff); \
	tmp3 = ((unsigned long)L >> 16); \
	tmp3 = ((unsigned long)tmp3 & 0xff); \
	tmp4 = ((unsigned long)L >> 24); \
	tmp1 = ctx_S.S[3][tmp1]; \
	tmp2 = ctx_S.S[2][tmp2]; \
	tmp3 = ctx_S.S[1][tmp3]; \
        tmp3 = (unsigned long)((unsigned long)tmp3 + (unsigned long)ctx_S.S[0][tmp4]); \
	tmp3 ^= tmp2; \
	R =R ^ ctx_P[N + 1]; \
	tmp3 = (unsigned long)((unsigned long)tmp3 + (unsigned long)tmp1); \
	R =R ^ tmp3;

#define BF_ENCRYPT(ctx_S,ctx_P, L, R) \
	L ^= ctx_P[0]; \
	BF_ROUND(ctx_S,ctx_P, L, R, 0, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 1, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 2, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 3, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 4, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 5, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 6, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 7, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 8, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 9, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 10, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 11, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 12, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 13, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 14, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P,R, L, 15, u1, u2, u3, u4); \
	u4 = R; \
	R = L; \
	L = u4 ^ ctx_P[BF_ROUNDS + 1];

#define BF_body() \
	L0 = R0 = 0; \
	ptr0 = BF_current_P; \
	do { \
		BF_ENCRYPT(BF_current_S INDEX,BF_current_P , L0, R0); \
		*ptr0 = L0; \
		*(ptr0 + 1) = R0; \
		ptr0 += 2; \
	} while (ptr0 < &BF_current_P [BF_ROUNDS + 2]); \
\
	ptr2 = BF_current_S INDEX.S[0]; \
	do { \
		ptr2 += 2; \
		BF_ENCRYPT(BF_current_S INDEX,BF_current_P , L0, R0); \
		*(ptr2 - 2) = L0; \
		*(ptr2 - 1) = R0; \
	} while (ptr2 < &BF_current_S INDEX.S[3][0xFF]);


__kernel void blowfish(const __global uint *salt_global,
		       const __global uint *BF_key_exp_global,
                             __global uint *BF_out,
                             __global struct BF_ctx_S *BF_current_S,
			     __global struct BF_ctx_P *BF_current_P_global,
			     uint rounds	)
{	
	int index = get_global_id(0);
        int lid   = get_local_id(0); 
        __local uint salt[4];
        
	if(lid==0){  
	salt[0]=salt_global[0];
        salt[1]=salt_global[1];
	salt[2]=salt_global[2];
	salt[3]=salt_global[3];
       }
	
	barrier(CLK_LOCAL_MEM_FENCE);
       
	int i;
        __private uint BF_key_exp[18];
	uint BF_current_P[18];
	
	for(i=0;i<18;i++){ 
		BF_key_exp[i]=BF_key_exp_global[18*index+i];
		BF_current_P[i]=BF_current_P_global INDEX.P[i];
	      }
	
              
		uint L0, R0;
		uint u1, u2, u3, u4;
		uint *ptr0;
		uint count;
		__global uint *ptr2;
				
		L0 = R0 = 0;
		for (i = 0; i < BF_ROUNDS + 2; i += 2) {
			L0 ^= salt[i & 2];
			R0 ^= salt[(i & 2) + 1];
			BF_ENCRYPT(BF_current_S INDEX,BF_current_P , L0, R0);
			BF_current_P[i] = L0;
			BF_current_P[i + 1] = R0;
		}
		
		ptr2 = BF_current_S INDEX.S[0];
		do {
			ptr2 += 4;
			L0 ^= salt[(BF_ROUNDS + 2) & 3];
			R0 ^= salt[(BF_ROUNDS + 3) & 3];
			BF_ENCRYPT(BF_current_S INDEX,BF_current_P , L0, R0);
			*(ptr2 - 4) = L0;
			*(ptr2 - 3) = R0;
			L0 ^= salt[(BF_ROUNDS + 4) & 3];
			R0 ^= salt[(BF_ROUNDS + 5) & 3];
			BF_ENCRYPT(BF_current_S INDEX,BF_current_P  , L0, R0);
			*(ptr2 - 2) = L0;
			*(ptr2 - 1) = R0;
		} while (ptr2 < &BF_current_S INDEX.S[3][0xFF]);
               
		count = 1 << rounds;
		  
		do {
			BF_current_P[0] ^= BF_key_exp[0];
			BF_current_P[1] ^= BF_key_exp[1];
			BF_current_P[2] ^= BF_key_exp[2];
			BF_current_P[3] ^= BF_key_exp[3];
			BF_current_P[4] ^= BF_key_exp[4];
			BF_current_P[5] ^= BF_key_exp[5];
			BF_current_P[6] ^= BF_key_exp[6];
			BF_current_P[7] ^= BF_key_exp[7];
			BF_current_P[8] ^= BF_key_exp[8];
			BF_current_P[9] ^= BF_key_exp[9];
			BF_current_P[10] ^= BF_key_exp[10];
			BF_current_P[11] ^= BF_key_exp[11];
			BF_current_P[12] ^= BF_key_exp[12];
			BF_current_P[13] ^= BF_key_exp[13];
			BF_current_P[14] ^= BF_key_exp[14];
			BF_current_P[15] ^= BF_key_exp[15];
			BF_current_P[16] ^= BF_key_exp[16];
			BF_current_P[17] ^= BF_key_exp[17];
	 
			BF_body();
			
			u1 = salt[0];
			u2 = salt[1];
			u3 = salt[2];
			u4 = salt[3];
			BF_current_P[0] ^= u1;
			BF_current_P[1] ^= u2;
			BF_current_P[2] ^= u3;
			BF_current_P[3] ^= u4;
			BF_current_P[4] ^= u1;
			BF_current_P[5] ^= u2;
			BF_current_P[6] ^= u3;
			BF_current_P[7] ^= u4;
			BF_current_P[8] ^= u1;
			BF_current_P[9] ^= u2;
			BF_current_P[10] ^= u3;
			BF_current_P[11] ^= u4;
			BF_current_P[12] ^= u1;
			BF_current_P[13] ^= u2;
			BF_current_P[14] ^= u3;
			BF_current_P[15] ^= u4;
			BF_current_P[16] ^= u1;
			BF_current_P[17] ^= u2;

			BF_body();
		    
		} while (--count);
		
 		
		L0 = 0x4F727068;
		R0 = 0x65616E42;

		count = 64;
		
		do {
			BF_ENCRYPT(BF_current_S INDEX,BF_current_P , L0, R0);
		} while (--count);
		
		BF_out[2*index]=L0;
		BF_out[2*index+1]=R0;

	    for(i=0;i<18;i++)
		BF_current_P_global INDEX.P[i]=BF_current_P[i]; 

}




  