#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "polyfill.h"

size_t malloc_usable_size (const void *ptr){
  char *data = (char*)ptr;
  int64_t address =  (int64_t)ptr;
  if (address > 0x100000000l){
    data -= 4;
    return *((int*)data) - 0x10; /* that's the 64 bit malloc overhead */
  } else{
    data -= 4;
#ifdef _LP64
    return *((int*)data) - 0x10; /* that's the 31 bit malloc overhead */
#else
    return *((int*)data) - 0x08; /* that's the 31 bit malloc overhead */
#endif
  }
}

#ifdef __MVS__
void execChildError(const char *what){
  int savedErrno = errno;
  unsigned int reason = (unsigned int)__errno2();
  char buf[160];
  int len = snprintf(buf, sizeof(buf), "quickjs: exec: %s: errno=%d errno2=%08X\n",
                     what, savedErrno, reason);
  if (len > 0) {
    if (len > (int)sizeof(buf) - 1) {
      len = (int)sizeof(buf) - 1;
    }
    if (write(2, buf, len) < 0) {
      /* nothing more can be done from the child */
    }
  }
  errno = savedErrno;
}
#endif

// zosCas32/64 = z/OS Compare And Swap
static _Bool zosCas32(uint32_t *place, uint32_t *expected, uint32_t desired){
  uint32_t oldValue = *expected;
  int pswMask = 0;
#ifdef _LP64
  int64_t addr = (int64_t)place;
  __asm("         L  9,%0    \n"
        "         L  10,%2   \n"
        "         LG 11,%3   \n"
        "         CS 9,10,0(11) \n"
        "         ST 9,%0    \n"
        "         EPSW 10,0  \n"
        "         ST 10,%1   "
        : "+m"(oldValue), "=m"(pswMask)
        : "m"(desired), "m"(addr)
        : "r9","r10","r11","memory");
#else
  int32_t addr = (int32_t)place;
  __asm("         L  9,%0    \n"
        "         L  10,%2   \n"
        "         L  11,%3   \n"
        "         CS 9,10,0(11) \n"
        "         ST 9,%0    \n"
        "         EPSW 10,0  \n"
        "         ST 10,%1   "
        : "+m"(oldValue), "=m"(pswMask)
        : "m"(desired), "m"(addr)
        : "r9","r10","r11","memory");
#endif
  *expected = oldValue;
  return (_Bool)((pswMask & 0x3000) == 0);
}

static _Bool zosCas64(uint64_t *place, uint64_t *expected, uint64_t desired){
  uint64_t oldValue = *expected;
  int pswMask = 0;
#ifdef _LP64
  int64_t addr = (int64_t)place;
  __asm("         LG  9,%0    \n"
        "         LG  10,%2   \n"
        "         LG  11,%3   \n"
        "         CSG 9,10,0(11) \n"  // COMPARE AND SWAP (64-bit)
        "         STG 9,%0    \n"
        "         EPSW 10,0   \n"
        "         ST  10,%1   "
        : "+m"(oldValue), "=m"(pswMask)
        : "m"(desired), "m"(addr)
        : "r9","r10","r11","memory");
#else
  int32_t addr = (int32_t)place;
  __asm("         LM  8,9,%0   \n"
        "         LM  10,11,%2 \n"
        "         L   12,%3    \n"
        "         CDS 8,10,0(12) \n"  // COMPARE DOUBLE AND SWAP
        "         STM 8,9,%0   \n"
        "         EPSW 12,0    \n"
        "         ST  12,%1    "
        : "+m"(oldValue), "=m"(pswMask)
        : "m"(desired), "m"(addr)
        : "r8","r9","r10","r11","r12","memory");
#endif
  *expected = oldValue;
  return (_Bool)((pswMask & 0x3000) == 0);
}

int32_t atomicIncrementI32(int32_t *place, int32_t increment){
  uint32_t oldValue = *(uint32_t *)place;
  uint32_t newValue;
  do {
    newValue = oldValue + (uint32_t)increment;
  } while (!zosCas32((uint32_t *)place, &oldValue, newValue));
  return (int32_t)oldValue;
}


/*
struct timespec {
        time_t   tv_sec;        -- seconds 
        long     tv_nsec;       -- nanoseconds 
};
*/

#define STCK_MICRO_SHIFT 12
static const uint64_t unixSecondsAfterZ = UINT64_C(2208988800);

/* this ain't great, but it's better than nothing */

int clock_gettime(clockid_t clk_id, struct timespec *tp){
  uint64_t stck;
#ifdef _LP64
  __asm(" STCK %0 "
	: : "m"(stck): "r15");
  long micros = (long)(stck&0xFFF);
  time_t unixSeconds = (time_t)((stck >> STCK_MICRO_SHIFT) - unixSecondsAfterZ);

  switch (clk_id){
  case CLOCK_REALTIME:
  case CLOCK_MONOTONIC:
    tp->tv_sec = unixSeconds;
    tp->tv_nsec = (micros * 1000);
    return 0;
  default:
    {
      printf("*** PANIC *** unhandled clockid_t=%d\n",clk_id);
      return EINVAL; /* 22 */
    }
  }
#else
  return 0; /* fix me */
#endif
}

int convertOpenStream(int fd, unsigned short fileCCSID){
  struct f_cnvrt conversionArg;
  conversionArg.cvtcmd = SETCVTON; /* SETCVTOFF; */
  conversionArg.pccsid = 0;
  conversionArg.fccsid = fileCCSID; /* 1047; */
  int res = fcntl(fd, F_CONTROL_CVT, &conversionArg);
  return res;
}

#define CCSID_BINARY 65535
#define CCSID_NONE 0

int tagFile(const char *pathname, unsigned short ccsid){
#if defined(_LP64) && defined(ZCOMPILE_CLANG)
  attrib64_t attr;
  memset(&attr,0,sizeof(attrib64_t));

  attr.att_filetagchg = 1;
  attr.att_filetag.ft_ccsid = ccsid;
  if (ccsid == CCSID_NONE || ccsid == CCSID_BINARY ) {
    attr.att_filetag.ft_txtflag = 0;
  } else {
    attr.att_filetag.ft_txtflag = 1;
  }

  int res = __chattr64((char*)pathname, &attr, sizeof(attr));
#else
  attrib_t attr;
  memset(&attr,0,sizeof(attrib_t));

  attr.att_filetagchg = 1;
  attr.att_filetag.ft_ccsid = ccsid;
  if (ccsid == CCSID_NONE || ccsid == CCSID_BINARY ) {
    attr.att_filetag.ft_txtflag = 0;
  } else {
    attr.att_filetag.ft_txtflag = 1;
  }

  int res = __chattr((char*)pathname, &attr, sizeof(attr));
#endif

  return res;
}

#define EXTATTR_SHARELIB 0x10
#define EXTATTR_NO_SHAREAS 0x08
#define EXTATTR_APF_AUTH 0x04
#define EXTATTR_PROGCTL 0x02

int changeExtendedAttributes(const char *pathname, int attribute, bool onOff){
#if defined(_LP64) && defined(ZCOMPILE_CLANG)
  attrib64_t attr;
  memset(&attr,0,sizeof(attrib64_t));

  attr.att_setgen = 1;
  switch (attribute){
  case EXTATTR_SHARELIB:
    attr.att_sharelibmask = 1;
    attr.att_sharelib = (onOff ? 1 : 0);
    break;
  case EXTATTR_NO_SHAREAS:
    attr.att_noshareasmask = 1;
    attr.att_noshareas = (onOff ? 1 : 0);
    break;
  case EXTATTR_APF_AUTH:
    attr.att_apfauthmask = 1;
    attr.att_apfauth = (onOff ? 1 : 0);
    break;
  case EXTATTR_PROGCTL:
    attr.att_progctlmask = 1;
    attr.att_progctl = (onOff ? 1 : 0);
    break;
  }

  int res = __chattr64((char*)pathname, &attr, sizeof(attr));
#else
  attrib_t attr;
  memset(&attr,0,sizeof(attrib_t));

  attr.att_setgen = 1;
  switch (attribute){
  case EXTATTR_SHARELIB:
    attr.att_sharelibmask = 1;
    attr.att_sharelib = (onOff ? 1 : 0);
    break;
  case EXTATTR_NO_SHAREAS:
    attr.att_noshareasmask = 1;
    attr.att_noshareas = (onOff ? 1 : 0);
    break;
  case EXTATTR_APF_AUTH:
    attr.att_apfauthmask = 1;
    attr.att_apfauth = (onOff ? 1 : 0);
    break;
  case EXTATTR_PROGCTL:
    attr.att_progctlmask = 1;
    attr.att_progctl = (onOff ? 1 : 0);
    break;
  }

  int res = __chattr((char*)pathname, &attr, sizeof(attr));
#endif

  return res;
}

static uint32_t zosSubwordShift(const volatile void *p, int width, uint32_t **outWord){
  uintptr_t addr = (uintptr_t)p;
  uintptr_t wordAddr = addr & ~(uintptr_t)3;
  *outWord = (uint32_t *)wordAddr;
  /* z/Architecture is big-endian: byte 0 of the word is the MSB. */
  return (uint32_t)((4 - width - (int)(addr - wordAddr)) * 8);
}

#define ZOS_WORD_RMW(NAME, PTRTYPE, CTYPE, EXPR) \
CTYPE NAME(PTRTYPE *p, CTYPE x){ \
  uint32_t oldValue = *(uint32_t *)p; \
  uint32_t newValue; \
  CTYPE oldSub; \
  do { \
    oldSub = (CTYPE)oldValue; \
    newValue = (uint32_t)(CTYPE)(EXPR); \
  } while (!zosCas32((uint32_t *)p, &oldValue, newValue)); \
  return oldSub; \
}

#define ZOS_DWORD_RMW(NAME, CTYPE, EXPR) \
CTYPE NAME(_Atomic(CTYPE) *p, CTYPE x){ \
  uint64_t oldValue = *(uint64_t *)p; \
  uint64_t newValue; \
  CTYPE oldSub; \
  do { \
    oldSub = (CTYPE)oldValue; \
    newValue = (uint64_t)(CTYPE)(EXPR); \
  } while (!zosCas64((uint64_t *)p, &oldValue, newValue)); \
  return oldSub; \
}

#define ZOS_SUBWORD_RMW(NAME, CTYPE, WIDTH, MASK, EXPR) \
CTYPE NAME(_Atomic(CTYPE) *p, CTYPE x){ \
  uint32_t *word; \
  uint32_t shift = zosSubwordShift(p, (WIDTH), &word); \
  uint32_t oldWord = *word; \
  uint32_t newWord; \
  CTYPE oldSub; \
  do { \
    oldSub = (CTYPE)((oldWord >> shift) & (MASK)); \
    CTYPE newSub = (CTYPE)(EXPR); \
    newWord = (oldWord & ~((MASK) << shift)) | (((uint32_t)newSub & (MASK)) << shift); \
  } while (!zosCas32(word, &oldWord, newWord)); \
  return oldSub; \
}

/* ADD */
ZOS_WORD_RMW(atomicAddInt, int, int, oldSub + x)
ZOS_DWORD_RMW(atomicAddU64, uint64_t, oldSub + x)
ZOS_WORD_RMW(atomicAddU32, _Atomic(uint32_t), uint32_t, oldSub + x)
ZOS_SUBWORD_RMW(atomicAddU16, uint16_t, 2, 0xFFFFu, oldSub + x)
ZOS_SUBWORD_RMW(atomicAddU8, uint8_t, 1, 0xFFu, oldSub + x)

/* SUB */
ZOS_WORD_RMW(atomicSubInt, int, int, oldSub - x)
ZOS_DWORD_RMW(atomicSubU64, uint64_t, oldSub - x)
ZOS_WORD_RMW(atomicSubU32, _Atomic(uint32_t), uint32_t, oldSub - x)
ZOS_SUBWORD_RMW(atomicSubU16, uint16_t, 2, 0xFFFFu, oldSub - x)
ZOS_SUBWORD_RMW(atomicSubU8, uint8_t, 1, 0xFFu, oldSub - x)

/* AND */
ZOS_WORD_RMW(atomicAndInt, int, int, oldSub & x)
ZOS_DWORD_RMW(atomicAndU64, uint64_t, oldSub & x)
ZOS_WORD_RMW(atomicAndU32, _Atomic(uint32_t), uint32_t, oldSub & x)
ZOS_SUBWORD_RMW(atomicAndU16, uint16_t, 2, 0xFFFFu, oldSub & x)
ZOS_SUBWORD_RMW(atomicAndU8, uint8_t, 1, 0xFFu, oldSub & x)

/* OR */
ZOS_WORD_RMW(atomicOrInt, int, int, oldSub | x)
ZOS_DWORD_RMW(atomicOrU64, uint64_t, oldSub | x)
ZOS_WORD_RMW(atomicOrU32, _Atomic(uint32_t), uint32_t, oldSub | x)
ZOS_SUBWORD_RMW(atomicOrU16, uint16_t, 2, 0xFFFFu, oldSub | x)
ZOS_SUBWORD_RMW(atomicOrU8, uint8_t, 1, 0xFFu, oldSub | x)

/* XOR */
ZOS_WORD_RMW(atomicXorInt, int, int, oldSub ^ x)
ZOS_DWORD_RMW(atomicXorU64, uint64_t, oldSub ^ x)
ZOS_WORD_RMW(atomicXorU32, _Atomic(uint32_t), uint32_t, oldSub ^ x)
ZOS_SUBWORD_RMW(atomicXorU16, uint16_t, 2, 0xFFFFu, oldSub ^ x)
ZOS_SUBWORD_RMW(atomicXorU8, uint8_t, 1, 0xFFu, oldSub ^ x)

/* LOAD */
int atomicLoadInt(int *p){
  int old = *p;
  return old;
}

uint64_t atomicLoadU64(_Atomic(uint64_t) *p){
  uint64_t old = *p;
  return old;
}

uint32_t atomicLoadU32(_Atomic(uint32_t) *p){
  uint32_t old = *p;
  return old;
}

uint16_t atomicLoadU16(_Atomic(uint16_t) *p){
  uint16_t old = *p;
  return old;
}

uint8_t atomicLoadU8(_Atomic(uint8_t) *p){
  uint8_t old = *p;
  return old;
}

/* STORE */
void atomicStoreInt(int *p, int x){
  *p = x;
}

void atomicStoreU64(_Atomic(uint64_t) *p, uint64_t x){
  *p = x;
}

void atomicStoreU32(_Atomic(uint32_t) *p, uint32_t x){
  *p = x;
}

void atomicStoreU16(_Atomic(uint16_t) *p, uint16_t x){
  *p = x;
}

void atomicStoreU8(_Atomic(uint8_t) *p, uint8_t x){
  *p = x;
}

/* Exchange */
ZOS_WORD_RMW(atomicExchangeInt, int, int, x)
ZOS_DWORD_RMW(atomicExchangeU64, uint64_t, x)
ZOS_WORD_RMW(atomicExchangeU32, _Atomic(uint32_t), uint32_t, x)
ZOS_SUBWORD_RMW(atomicExchangeU16, uint16_t, 2, 0xFFFFu, x)
ZOS_SUBWORD_RMW(atomicExchangeU8, uint8_t, 1, 0xFFu, x)

_Bool atomicCompareExchangeStrongInt(int *p, int *exp, int desired){
  uint32_t oldValue = (uint32_t)*exp;
  _Bool ok = zosCas32((uint32_t *)p, &oldValue, (uint32_t)desired);
  *exp = (int)oldValue;
  return ok;
}

_Bool atomicCompareExchangeStrongU64(_Atomic(uint64_t) *p, uint64_t *exp, uint64_t desired){
  return zosCas64((uint64_t *)p, exp, desired);
}

_Bool atomicCompareExchangeStrongU32(_Atomic(uint32_t) *p, uint32_t *exp, uint32_t desired){
  return zosCas32((uint32_t *)p, exp, desired);
}

_Bool atomicCompareExchangeStrongU16(_Atomic(uint16_t) *p, uint16_t *exp, uint16_t desired){
  uint32_t *word;
  uint32_t shift = zosSubwordShift(p, 2, &word);
  uint32_t oldWord = *word;
  for (;;) {
    uint16_t curSub = (uint16_t)((oldWord >> shift) & 0xFFFFu);
    if (curSub != *exp) { *exp = curSub; return false; }
    uint32_t newWord = (oldWord & ~(0xFFFFu << shift)) | ((uint32_t)desired << shift);
    if (zosCas32(word, &oldWord, newWord)) return true;
  }
}

_Bool atomicCompareExchangeStrongU8(_Atomic(uint8_t) *p, uint8_t *exp, uint8_t desired){
  uint32_t *word;
  uint32_t shift = zosSubwordShift(p, 1, &word);
  uint32_t oldWord = *word;
  for (;;) {
    uint8_t curSub = (uint8_t)((oldWord >> shift) & 0xFFu);
    if (curSub != *exp) { *exp = curSub; return false; }
    uint32_t newWord = (oldWord & ~(0xFFu << shift)) | ((uint32_t)desired << shift);
    if (zosCas32(word, &oldWord, newWord)) return true;
  }
}
