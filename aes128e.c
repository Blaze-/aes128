#include "aes128e.h"

/* Multiplication by two in GF(2^8). Multiplication by three is xtime(a) ^ a */
#define xtime(a) ( ((a) & 0x80) ? (((a) << 1) ^ 0x1b) : ((a) << 1) )

/* The S-box table */
static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

/* The round constant table (needed in KeyExpansion) */
static const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36 };

void addRoundKey(unsigned char state[4][4], word* roundKey, int round) {
  for (int row = 0; row < 4; row++) {
      state[row][0] ^= (roundKey[round*4+row] >> 24);
      state[row][1] ^= (roundKey[round*4+row] << 8) >> 24;
      state[row][2] ^= (roundKey[round*4+row] << 16) >> 24;
      state[row][3] ^= (roundKey[round*4+row] << 24) >> 24;
  }
}

word toWord(const unsigned char* bytes) {
  word t = 0;
  t = t | (bytes[3]);
  t = t |  (bytes[2] << 8);
  t = t | (bytes[1] << 16);
  t = t | (bytes[0] << 24);
  return t;
}

void subWord(word *w) {
  word tmp = *w;
  *w = 0x0;
  unsigned char t[4];
  //do the substitions byte by byte
  t[0] = sbox[tmp >> 24];
  t[1] = sbox[(tmp << 8) >> 24];
  t[2] = sbox[(tmp << 16) >> 24];
  t[3] = sbox[(tmp << 24) >> 24];
  //merge all substituted bytes
  *w = t[0];
  *w = (*w << 8) | t[1];
  *w = (*w << 8) | t[2];
  *w = (*w << 8) | t[3];
}

void rotWord(word *w) {
  word tmp = *w;
  *w = (*w << 8);
  *w = (*w) | (tmp >> 24);
}

void keyExpansion(const unsigned char *key, word *roundK) {

  int i = 0;
  while (i < 4) {
    roundK[i] = toWord(&key[4*i]);
    i++;
  }
  i = 4;
  while (i < 44) {
    word tmp = roundK[i - 1];
    if (i % 4 == 0) {
      rotWord(&tmp);
      subWord(&tmp);
      tmp = (tmp)^(rcon[i/4 - 1] << 24);
    }
    roundK[i] = roundK[i - 4]^(tmp);
    i++;
  }
}


void mixColumns(unsigned char state[4][4]) {
  for (int column = 0; column < 4; column++) {
  unsigned char tmp[4];
    tmp[0] = xtime(state[column][0])^(xtime(state[column][1])^state[column][1])^state[column][2]^state[column][3];

    tmp[1] = xtime(state[column][1])^
      state[column][0]^(xtime(state[column][2])^state[column][2])^state[column][3];

    tmp[2] = state[column][0]^state[column][1]^
      (xtime(state[column][2]))^(xtime(state[column][3])^state[column][3]);

    tmp[3] = (xtime(state[column][0])^state[column][0])^
      state[column][1]^state[column][2]^xtime(state[column][3]);

    state[column][0] = tmp[0];
    state[column][1] = tmp[1];
    state[column][2] = tmp[2];
    state[column][3] = tmp[3];
  }
}

void subBytes(unsigned char state[4][4]) {
  for (int row = 0; row < 4; row++) {
    for (int column = 0; column < 4; column++) {
      state[row][column] = sbox[state[row][column]];
    }
  }
}

void shiftRows(unsigned char state[4][4]) {
  unsigned char tmp = state[0][1];
  state[0][1] = state[1][1];
  state[1][1] = state[2][1];
  state[2][1] = state[3][1];
  state[3][1] = tmp;

  tmp = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = tmp;
  tmp = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = tmp;

  unsigned char tmp2[4];
  tmp2[0] = state[0][3];
  tmp2[1] = state[1][3];
  tmp2[2] = state[2][3];
  tmp2[3] = state[3][3];
  state[0][3] = tmp2[3];
  state[1][3] = tmp2[0];
  state[2][3] = tmp2[1];
  state[3][3] = tmp2[2];
 }

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
 void printState(unsigned char state[4][4]) {
  int row = 0;
  int column = 0;
  for (; row < 4; row++) {
    for ( column = 0; column < 4; column++) {
  printf("%x ", state[row][column]);
    }
    printf("\n");
  }
}
void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k) {
  int Nb = 4;
  int Nk = 4;
  int Nr = 10;
  int round = 0;
  word roundKey[44];
  keyExpansion(k, roundKey);

   unsigned char state[4][4];
  /*fill the state matrix */

  int row = 0;
  int column = 0;
  for (; row < 4; row++) {
    for ( column = 0; column < 4; column++) {
      state[row][column] = p[row*4+column];
    }
  }

  addRoundKey(state, roundKey, round);

  for (round=1; round < 10; round++) {

    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKey, round);

    }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKey, 10);
  for (int row = 0; row < 4; row++) {
    for (int column = 0; column < 4; column++) {
      c[4*row+column] = state[row][column];
    }
   }
}
