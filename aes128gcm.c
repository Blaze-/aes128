#include "aes128gcm.h"
#include "aes128e.h"
#include <stdio.h>
#include <math.h>

#define BLOCK_SIZE 16

/* prints a block to stdout*/
void print_block(const unsigned char *b) {
    int i = 0;
    for (; i < 16; i++) {
        printf("%x", b[i]);
    }
    printf("\n");
}

/* returns last 4 bytes of block as uint32 */
uint32_t get_int32_from_bytes(unsigned char *bytes) {
  uint32_t res_val = 0x0;
  res_val |= (uint32_t)bytes[3];
  res_val |= (uint32_t)(bytes[2] << 8);
  res_val |= (uint32_t)(bytes[1] << 16);
  res_val |= (uint32_t)(bytes[0] << 24);
  return res_val;
}

void insert_int64_to_block(unsigned char *bytes, uint64_t value) {
  bytes[0] = (unsigned char)(value >> 56);
  bytes[1] = (unsigned char)(value >> 48);
  bytes[2] = (unsigned char)(value >> 40);
  bytes[3] = (unsigned char)(value >> 32);
  bytes[4] = (unsigned char)(value >> 24);
  bytes[5] = (unsigned char)(value >> 16);
  bytes[6] = (unsigned char)(value >> 8);
  bytes[7] = (unsigned char)(value);
}

/* insert given unsigned integer to the block*/
void insert_int32_to_block(unsigned char *bytes, uint32_t value) {
  bytes[0] = (unsigned char)(value >> 24);
  bytes[1] = (unsigned char)(value >> 16);
  bytes[2] = (unsigned char)(value >> 8);
  bytes[3] = (unsigned char)(value);
}

/*get the nth bit of block*/
int get_bit(unsigned char *bytes, int position_in_block) {
    int byte = position_in_block/8;
    int position =  7 - position_in_block % 8;
    return (bytes[byte] & (1 << position));

}
/* shift the block to the right by one */
void shift_block(unsigned char *bytes) {
     int i;
     for (i = 15; i > 0; i--) { 
      bytes[i] = bytes[i] >> 1; 
      if (bytes[i-1] & (1 << 7) != 0) { 
        bytes[i] |= 128;
      }
    }
    bytes[0] = bytes[0] >> 1;
}



void inc32(unsigned char *X) {
  uint32_t d = get_int32_from_bytes(X+12) + 1;
  insert_int32_to_block(X+12, d); 
}

/* XOR block byte by byte */
void xor_block(unsigned char *a, const unsigned char *b) {
    int i;
    for (i = 0; i < BLOCK_SIZE; i++) {
      a[i] ^= b[i];
    }
}

/*multiply two blocks and store the result in Z*/

void mul_block(unsigned char *X, unsigned char *Y, unsigned char *Z) {
  int i;
  memset(Z, 0, 16); 
  unsigned char V[BLOCK_SIZE];
  memset(V, 0, 16);
  memcpy(V, Y, 16); 

  for (i = 0; i < 8*BLOCK_SIZE; i++) {
    if (get_bit(X,i) != 0) {
          xor_block(Z, V);
      }
      if (V[15] & 1) { 
          shift_block(V);
          V[0] ^= 0xe1;    
      } else { 
          shift_block(V);
      }
  }
}

void ghash(unsigned char *X, int len_x, unsigned char *H, unsigned char *Y) {
      memset(Y, 0, 16); 
      int i;
      for (i = 0; i < len_x; i++) {
          unsigned char tmp[16]; 
          memset(tmp, 0, 16);
          xor_block(Y, X+i*16); 
          mul_block(Y, H, tmp);
          memcpy(Y, tmp, 16); 
      }
}

//void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k) 
void gctr(const unsigned char *ICB, const unsigned char *X, int len_x, const unsigned char *K, unsigned char *Y) {
    if (len_x == 0) { 
      Y = NULL;
      return;
    }
    int n = len_x; 
    int i; 
    unsigned char CB[16];
    memset(CB, 0, 16);  
    memcpy(CB, ICB, 16);  
    for (i = 0; i < n; i++) {
        unsigned char tmp[16]; 
        memset(tmp, 0, 16);
        aes128e(tmp, CB, K); 
        xor_block(tmp, X+i*16); 
        memcpy(Y+i*16, tmp, 16);
        inc32(CB);
    }

}


/* Under the 16-byte (128-bit) key "k",
and the 12-byte (96-bit) initial value "IV",
encrypt the plaintext "plaintext" and store it at "ciphertext".
The length of the plaintext is a multiple of 16-byte (128-bit) given by len_p (e.g., len_p = 2 for a 32-byte plaintext).
The length of the ciphertext "ciphertext" is len_p*16 bytes.
The authentication tag is obtained by the 16-byte tag "tag".
For the authentication an additional data "add_data" can be added.
The number of blocks for this additional data is "len_ad" (e.g., len_ad = 1 for a 16-byte additional data).
*/

void aes128gcm(unsigned char *ciphertext, unsigned char *tag, const unsigned char *k, 
  const unsigned char *IV, const unsigned char *plaintext, const unsigned long len_p, 
  const unsigned char* add_data, const unsigned long len_ad) {
  unsigned char tmp[16];
  memset(tmp, 0, 16);

  unsigned char H[16];
  memset(H, 0, 16);
  aes128e(H, tmp, k);
  memset(tmp, 0, 16);

  unsigned char J0[16];
  memset(J0, 0, 16);
  memcpy(J0, IV, 12);
  J0[15] |= 0x1;

  unsigned char J0inc[16];
  memset(J0inc, 0, 16);
  memcpy(J0inc, J0, 16);
  inc32(J0inc);
  gctr(J0inc, plaintext, len_p, k, ciphertext);

  unsigned char S[16];
  memset(S, 0, 16);
  unsigned char tmp2[(len_p+len_ad+1)*16]; 
  memset(tmp2, 0, (len_p+len_ad+1)*16);
  int i;
  for (i = 0; i < len_ad; i++) {
    memcpy(tmp2+i*16, add_data+i*16, 16);
  }
  int a = 0;
  for (i = len_ad; i < len_ad+len_p; i++) {
    memcpy(tmp2+i*16, ciphertext+a*16, 16);  
    a++;
  }
  insert_int64_to_block(tmp2+(len_p+len_ad)*16, (uint64_t)(len_ad*128));
  insert_int64_to_block(tmp2+(len_p+len_ad)*16+8, (uint64_t)(len_p*128));
  ghash(tmp2, len_p+len_ad+1, H, S);

  gctr(J0, S, 1, k, tag);

}



