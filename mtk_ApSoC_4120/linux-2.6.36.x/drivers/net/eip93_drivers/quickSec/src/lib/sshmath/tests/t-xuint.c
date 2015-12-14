/*

  t-xuint.h

  Copyright:
          Copyright (c) 2007 SFNT Finland Oy.
  All rights reserved.

  Created: Mon Feb  5 13:23:18 EET 2007 [mnippula]

  Testing implementation of 128/64-bit extended integer type.
  */

#include "sshmp-xuint.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define C4(a1,a2,a3,a4) (int)a1,(int)a2,(int)a3,(int)a4
#define C2(a1,a2) (int)a1,(int)a2

void test_failed( void ) { /* Function only called after a test failed... */ }

#define DUMP64(op,x1,x2,y1,y2,z1,z2,r) \
do { test_failed(); \
  fprintf(stderr, \
        "%s(0x%08x%08x,\n%*s 0x%08x%08x) !=\n%*s " \
        "0x%08x%08x, got\n%*s 0x%08x%08x\n", \
        #op, C2(x1,x2), \
        strlen(#op), "", C2(y1,y2), \
        strlen(#op), "", C2(z1,z2), \
        strlen(#op), "",                 \
        C2(SSH_XUINT64_EXTRACT_UINT32(r,1), \
           SSH_XUINT64_EXTRACT_UINT32(r,0)) \
); exit(1); } while(0)

#define OP64(op,x1,x2,y1,y2,z1,z2)                      \
do                                                      \
  { SSH_XUINT64_BUILD(a_,x2,x1);                        \
    SSH_XUINT64_BUILD(b_,y2,y1);                        \
    op(c_,a_,b_);                                       \
    if (SSH_XUINT64_EXTRACT_UINT32(c_,0)!=z2 ||         \
        SSH_XUINT64_EXTRACT_UINT32(c_,1)!=z1)           \
        DUMP64(op,x1,x2,y1,y2,z1,z2,c_);                \
  }                                                     \
while (0)

#define OP64I(op,x1,x2,y1,z1,z2)                        \
do                                                      \
  { SSH_XUINT64_BUILD(a_,x2,x1);                        \
    SSH_XUINT64_BUILD(b_,y1,0);                         \
    op(c_,a_,(y1));                                     \
    if (SSH_XUINT64_EXTRACT_UINT32(c_,0)!=z2 ||         \
        SSH_XUINT64_EXTRACT_UINT32(c_,1)!=z1)           \
        DUMP64(op,x1,x2,0,y1,z1,z2,c_);                 \
  }                                                     \
while (0)

#define DUMP128(op,x1,x2,x3,x4,y1,y2,y3,y4,z1,z2,z3,z4,r) \
do { test_failed(); \
  fprintf(stderr, \
        "%s(0x%08x%08x%08x%08x,\n%*s 0x%08x%08x%08x%08x) !=\n%*s " \
        "0x%08x%08x%08x%08x, got\n%*s 0x%08x%08x%08x%08x\n", \
        #op, C4(x1,x2,x3,x4), \
        strlen(#op), "", C4(y1,y2,y3,y4), \
        strlen(#op), "", C4(z1,z2,z3,z4), \
        strlen(#op), "",                 \
        C4(SSH_XUINT128_EXTRACT_UINT32(r,3), \
           SSH_XUINT128_EXTRACT_UINT32(r,2), \
           SSH_XUINT128_EXTRACT_UINT32(r,1), \
           SSH_XUINT128_EXTRACT_UINT32(r,0)) \
); exit(1); } while(0)

#define OP128(op,x1,x2,x3,x4,y1,y2,y3,y4,z1,z2,z3,z4)   \
do                                                      \
  { SSH_XUINT128_BUILD(a_,x4,x3,x2,x1);                 \
    SSH_XUINT128_BUILD(b_,y4,y3,y2,y1);                 \
    op(c_,a_,b_);                                       \
    if (SSH_XUINT128_EXTRACT_UINT32(c_,0)!=z4 ||        \
        SSH_XUINT128_EXTRACT_UINT32(c_,1)!=z3 ||        \
        SSH_XUINT128_EXTRACT_UINT32(c_,2)!=z2 ||        \
        SSH_XUINT128_EXTRACT_UINT32(c_,3)!=z1)          \
      DUMP128(op,x1,x2,x3,x4,y1,y2,y3,y4,z1,z2,z3,z4,c_); \
  }                                                     \
while (0)

#define OP128I(op,x1,x2,x3,x4,y1,z1,z2,z3,z4)           \
do                                                      \
  { SSH_XUINT128_BUILD(a_,x4,x3,x2,x1);                 \
    SSH_XUINT128_BUILD(b_,y1,0,0,0);                    \
    op(c_,a_,(y1));                                     \
    if (SSH_XUINT128_EXTRACT_UINT32(c_,0)!=z4 ||        \
        SSH_XUINT128_EXTRACT_UINT32(c_,1)!=z3 ||        \
        SSH_XUINT128_EXTRACT_UINT32(c_,2)!=z2 ||        \
        SSH_XUINT128_EXTRACT_UINT32(c_,3)!=z1)          \
      DUMP128(op,x1,x2,x3,x4,0,0,0,y1,z1,z2,z3,z4,c_);  \
  }                                                     \
while (0)

int test128( void )
{
  SshXUInt128 a_,b_,c_;
  OP128(SSH_XUINT128_ADD, 
	0x11223344,0x55667788,0x99aabbcc,0xddeeffff,
	0x00000000,0x00000000,0x00000000,0x00000001,
        0x11223344,0x55667788,0x99aabbcc,0xddef0000);

  OP128(SSH_XUINT128_ADD, 
	0x80000000,0x00000000,0x00000000,0x00000000,
	0x80000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000);

  OP128(SSH_XUINT128_ADD, 
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0x00000000,0x00000000,0x00000000,0x00000001,
	0x00000000,0x00000000,0x00000000,0x00000000);

  OP128(SSH_XUINT128_SUB,
	0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000001,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff);

  OP128(SSH_XUINT128_AND,
	0x00000000,0xffffffff,0x00000000,0xffffffff,
	0x00000000,0x00000000,0xffffffff,0xffffffff,
	0x00000000,0x00000000,0x00000000,0xffffffff);

  OP128(SSH_XUINT128_OR,
	0x00000000,0xffffffff,0x00000000,0xffffffff,
	0x00000000,0x00000000,0xffffffff,0xffffffff,
	0x00000000,0xffffffff,0xffffffff,0xffffffff);

  OP128(SSH_XUINT128_XOR,
	0x00000000,0xffffffff,0x00000000,0xffffffff,
	0x00000000,0x00000000,0xffffffff,0xffffffff,
	0x00000000,0xffffffff,0xffffffff,0x00000000);

  OP128I(SSH_XUINT128_ROL,
        0x00000000,0x00000000, 0x00000000, 0x00000001, 1,
        0x00000000,0x00000000, 0x00000000, 0x00000002);
  
  OP128I(SSH_XUINT128_ROR,
        0x00000000, 0x00000000, 0x00000000,0x00000001, 1,
        0x80000000, 0x00000000, 0x00000000,0x00000000);
  
  OP128I(SSH_XUINT128_ROL,
        0x00000000, 0x00000600, 0x01000000,0x80000000, 1,
        0x00000000, 0x00000c00, 0x02000001,0x00000000);
  
  OP128I(SSH_XUINT128_ROR,
        0x00000400, 0x00000001, 0x00000000,0x80000000, 1,
        0x00000200, 0x00000000, 0x80000000,0x40000000);
  
  OP128I(SSH_XUINT128_ROR,
        0x00000001, 0x00000000, 0xaaaaaaab,0x55555554, 1,
        0x00000000, 0x80000000, 0x55555555,0xaaaaaaaa);
   
  OP128I(SSH_XUINT128_ROL,
        0x00000000, 0x55500000, 0x55555555,0xaaaaaaaa, 1,
        0x00000000, 0xaaa00000, 0xaaaaaaab,0x55555554);
  
  OP128I(SSH_XUINT128_ROR,
        0x0ccc0000, 0x00000000, 0xaaaaaaab,0x55555554, 1,
        0x06660000, 0x00000000, 0x55555555,0xaaaaaaaa);
  
  OP128I(SSH_XUINT128_ROL,
        0x12345678, 0x00001234, 0x56780000, 0x9abc0def, 4,
        0x23456780, 0x00012345, 0x67800009, 0xabc0def1);
  
  OP128I(SSH_XUINT128_ROR,
        0x12345678, 0x00000000, 0x00000000, 0x9abc0def, 4,
        0xf1234567, 0x80000000, 0x00000000, 0x09abc0de);
  
  OP128I(SSH_XUINT128_SLL,
        0x12345678, 0x00001234, 0x56780000, 0x9abc0def, 4,
        0x23456780, 0x00012345, 0x67800009, 0xabc0def0);
  
  OP128I(SSH_XUINT128_SLR,
        0x12345678, 0x00000123, 0x04560000, 0x9abc0def, 4,
        0x01234567, 0x80000012, 0x30456000, 0x09abc0de);
  
  return 0;
}

int test64(void)
{
  SshXUInt64 a_,b_,c_;
  OP64(SSH_XUINT64_ADD, 
       0x99aabbcc,0xddeeffff,
       0x00000000,0x00000001,
       0x99aabbcc,0xddef0000);

  OP64(SSH_XUINT64_ADD, 
       0x80000000,0x00000000,
       0x80000000,0x00000000,
       0x00000000,0x00000000);

  OP64(SSH_XUINT64_ADD, 
       0xffffffff,0xffffffff,
       0x00000000,0x00000001,
       0x00000000,0x00000000);
  
  OP64(SSH_XUINT64_ADD, 
       0xffffffff,0xffffffff,
       0x00000000,0x00000002,
       0x00000000,0x00000001);
  
  OP64(SSH_XUINT64_SUB, 
       0x00000000,0x00000001,
       0x00000000,0x00000002,
       0xffffffff,0xffffffff);
  
  OP64(SSH_XUINT64_AND, 
       0x000000ff,0x00000001,
       0x000000ff,0x00000002,
       0x000000ff,0x00000000);
  
  OP64(SSH_XUINT64_OR, 
       0x000000ff,0x00000001,
       0x000000ff,0x00000002,
       0x000000ff,0x00000003);
  
  OP64(SSH_XUINT64_XOR, 
       0x000000ff,0x00000001,
       0x000000ff,0x00000002,
       0x00000000,0x00000003);

  OP64I(SSH_XUINT64_ROL,
        0x00000000,0x00000001, 1,
        0x00000000,0x00000002);
  
  OP64I(SSH_XUINT64_ROR,
        0x00000000,0x00000001, 1,
        0x80000000,0x00000000);
  
  OP64I(SSH_XUINT64_ROL,
        0x00000000,0x80000000, 1,
        0x00000001,0x00000000);
  
  OP64I(SSH_XUINT64_ROR,
        0x00000000,0x80000000, 1,
        0x00000000,0x40000000);
  
  OP64I(SSH_XUINT64_ROR,
        0xaaaaaaab,0x55555554, 1,
        0x55555555,0xaaaaaaaa);
   
  OP64I(SSH_XUINT64_ROL,
        0x55555555,0xaaaaaaaa, 1,
        0xaaaaaaab,0x55555554);
  
  OP64I(SSH_XUINT64_ROR,
        0xaaaaaaab,0x55555554, 1,
        0x55555555,0xaaaaaaaa);
  
  OP64I(SSH_XUINT64_ROL,
        0x12345678,0x9abc0def, 4,
        0x23456789,0xabc0def1);
  
  OP64I(SSH_XUINT64_ROR,
        0x12345678,0x9abc0def, 4,
        0xf1234567,0x89abc0de);
  
  OP64I(SSH_XUINT64_SLL,
        0x12345678,0x9abc0def, 4,
        0x23456789,0xabc0def0);
  
  OP64I(SSH_XUINT64_SLR,
        0x12345678,0x9abc0def, 4,
        0x01234567,0x89abc0de);
  
  return 0;
}

int main(void)
{
  test128();
  return test64();
}
