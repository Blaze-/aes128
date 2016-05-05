/* Implement the following API.
 * You can add your own functions, but don't modify below this line.
 */

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t word;

void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k);

void addRoundKey(unsigned char state[4][4],  word *roundKey, int round);

void subBytes(unsigned char state[4][4]);

void shiftRows(unsigned char state[4][4]);

void mixColumns(unsigned char state[4][4]);

void keyExpansion(const unsigned char *key, word *roundK);
