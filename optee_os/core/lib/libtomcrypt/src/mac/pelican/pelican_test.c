/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file pelican_test.c
   Pelican MAC, test, by Tom St Denis
*/

#ifdef LTC_PELICAN

int pelican_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
        unsigned char K[32], MSG[64], T[16];
   int keylen, ptlen;
   } tests[] = {
/* K=16, M=0 */
{
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
   { 0 },
   { 0xeb, 0x58, 0x37, 0x15, 0xf8, 0x34, 0xde, 0xe5,
     0xa4, 0xd1, 0x6e, 0xe4, 0xb9, 0xd7, 0x76, 0x0e, },
   16, 0
},

/* K=16, M=3 */
{
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
   { 0x00, 0x01, 0x02 },
   { 0x1c, 0x97, 0x40, 0x60, 0x6c, 0x58, 0x17, 0x2d,
     0x03, 0x94, 0x19, 0x70, 0x81, 0xc4, 0x38, 0x54, },
   16, 3
},

/* K=16, M=16 */
{
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
   { 0x03, 0xcc, 0x46, 0xb8, 0xac, 0xa7, 0x9c, 0x36,
     0x1e, 0x8c, 0x6e, 0xa6, 0x7b, 0x89, 0x32, 0x49, },
   16, 16
},

/* K=16, M=32 */
{
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
   { 0x89, 0xcc, 0x36, 0x58, 0x1b, 0xdd, 0x4d, 0xb5,
     0x78, 0xbb, 0xac, 0xf0, 0xff, 0x8b, 0x08, 0x15, },
   16, 32
},

/* K=16, M=35 */
{
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
     0x20, 0x21, 0x23 },
   { 0x4a, 0x7d, 0x45, 0x4d, 0xcd, 0xb5, 0xda, 0x8d,
     0x48, 0x78, 0x16, 0x48, 0x5d, 0x45, 0x95, 0x99, },
   16, 35
},
};
   int x, err;
   unsigned char out[16];
   pelican_state pel;

   for (x = 0; x < (int)(sizeof(tests)/sizeof(tests[0])); x++) {
       if ((err = pelican_init(&pel, tests[x].K, tests[x].keylen)) != CRYPT_OK) {
          return err;
       }
       if ((err = pelican_process(&pel, tests[x].MSG, tests[x].ptlen)) != CRYPT_OK) {
          return err;
       }
       if ((err = pelican_done(&pel, out)) != CRYPT_OK) {
          return err;
       }

       if (compare_testvector(out, 16, tests[x].T, 16, "PELICAN", x)) {
           return CRYPT_FAIL_TESTVECTOR;
       }
   }
   return CRYPT_OK;
#endif
}


#endif
