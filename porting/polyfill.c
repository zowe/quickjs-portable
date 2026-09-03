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

/* ---- Does Language Environment say the heap element header is untrustworthy?
 *
 * The runtime options in effect live in LE's Options Control Block, three
 * pointers from the CAA:   CAA -> EDB (CEECAAEDB) -> OCB (CEEEDBOPTCB).
 * The offsets below come from the CEECAA, CEEEDB and CEEOCB mappings in
 * CEE.SCEEMAC (SYSSTATE AMODE64=YES selects the 64-bit CAA and EDB forms;
 * the OCB layout is the same in both modes) and were verified on z/OS 3.1
 * under each option. Three things the mappings do not say: the 64-bit OCB's
 * eyecatcher is CELQOCB rather than CEEOCB; CEEOCB_*_SUB_OPTIONS holds an
 * offset within the OCB, not an address; HEAPZONES has no ON bit and must
 * be judged by its sizes.
 *
 * Every hop is checked. When anything looks wrong the answer is "active",
 * which costs a fast path, never memory safety.
 */

#ifdef _LP64
#define LE_CAA_EDB               0x388  /* CEECAAEDB    AD(EDB)      */
#define LE_CAA_SELF              0x3A0  /* CEECAAPTR    AD(this CAA) */
#define LE_EDB_OPTCB             0x110  /* CEEEDBOPTCB  AD(OCB)      */
#else
#define LE_CAA_EDB               0x2F0  /* CEECAAEDB    A(EDB)       */
#define LE_CAA_SELF              0x2FC  /* CEECAAPTR    A(this CAA)  */
#define LE_EDB_OPTCB             0x010  /* CEEEDBOPTCB  A(OCB)       */
#endif
#define LE_OCB_LENGTH            0x00A  /* CEEOCB_LENGTH                 H */
#define LE_OCB_HEAPCHK           0x1D4  /* CEEOCB_HEAPCHK_BIT_FLAG       X */
#define LE_OCB_HEAPPOOLS         0x1E4  /* CEEOCB_HEAPPOOLS_BIT_FLAG     X */
#define LE_OCB_HEAPPOOLS64       0x20C  /* CEEOCB_HEAPPOOLS64_BIT_FLAG   X */
#define LE_OCB_HEAPZONES_SUBOPTS 0x250  /* CEEOCB_HEAPZONES_SUB_OPTIONS  A, an offset */
#define LE_OCB_OPTION_ON         0x80   /* CEEOCB_*_ON                     */
#define LE_HEAPZONES_SIZE31      0x04   /* CEEOCB_HEAPZONES_SIZE31, in the sub-options */
#define LE_HEAPZONES_SIZE64      0x0C   /* CEEOCB_HEAPZONES_SIZE64                     */

/* EBCDIC: this file is compiled in ASCII char mode, so no string literals. */
static const unsigned char LE_EYE_CEEEDB[6]  = {0xC3,0xC5,0xC5,0xC5,0xC4,0xC2};      /* CEEEDB  */
static const unsigned char LE_EYE_CEEOCB[6]  = {0xC3,0xC5,0xC5,0xD6,0xC3,0xC2};      /* CEEOCB  */
static const unsigned char LE_EYE_CELQOCB[7] = {0xC3,0xC5,0xD3,0xD8,0xD6,0xC3,0xC2}; /* CELQOCB */

static char *leCAA(void){
#ifdef _LP64
  char *laa = *(char * __ptr32 * __ptr32)0x4B8;   /* PSALAA: the LE library anchor area */
  char *lca = *(char **)(laa + 0x58);             /* CEELAA_LCA64 */
  return *(char **)(lca + 0x08);                  /* CEELCA_CAA   */
#else
  char *caa;
  __asm("         LA    %0,0(,12)" : "=r"(caa));  /* R12 addresses the CAA in AMODE 31 */
  return caa;
#endif
}

static int leHeapCheckActive(void){
  char *caa = leCAA();
  if (caa == NULL || *(char **)(caa + LE_CAA_SELF) != caa) {
    return 1;
  }
  char *edb = *(char **)(caa + LE_CAA_EDB);
  if (edb == NULL || memcmp(edb, LE_EYE_CEEEDB, sizeof(LE_EYE_CEEEDB)) != 0) {
    return 1;
  }
  char *ocb = *(char **)(edb + LE_EDB_OPTCB);
  if (ocb == NULL ||
      (memcmp(ocb, LE_EYE_CELQOCB, sizeof(LE_EYE_CELQOCB)) != 0 &&
       memcmp(ocb, LE_EYE_CEEOCB,  sizeof(LE_EYE_CEEOCB))  != 0)) {
    return 1;
  }

  unsigned int zoneSize  = 0;
  unsigned int ocbLength = *(unsigned short *)(ocb + LE_OCB_LENGTH);
  unsigned int zonesRef  = *(unsigned int *)(ocb + LE_OCB_HEAPZONES_SUBOPTS);
  if (zonesRef != 0) {
    if (zonesRef >= ocbLength) {
      return 1;                                   /* not the offset we expect */
    }
#ifdef _LP64
    zoneSize = *(unsigned int *)(ocb + zonesRef + LE_HEAPZONES_SIZE64);
#else
    zoneSize = *(unsigned int *)(ocb + zonesRef + LE_HEAPZONES_SIZE31);
#endif
  }
#ifdef _LP64
  unsigned char pools = *(unsigned char *)(ocb + LE_OCB_HEAPPOOLS64);
#else
  unsigned char pools = *(unsigned char *)(ocb + LE_OCB_HEAPPOOLS);
#endif
  unsigned char heapchk = *(unsigned char *)(ocb + LE_OCB_HEAPCHK);

  return (pools & LE_OCB_OPTION_ON) != 0 ||
         zoneSize != 0 ||
         (heapchk & LE_OCB_OPTION_ON) != 0;
}

int isLEHeapCheckActive(void){
  /* Runtime options are fixed for the life of the enclave, so decide once.
     Two threads arriving together compute the same value; the race is benign. */
  static int active = -1;
  if (active < 0) {
    active = leHeapCheckActive();
  }
  return active;
}

/* ---- malloc_usable_size --------------------------------------------------
 *
 * LE keeps the length of a heap element in the header just before the storage
 * it hands out: a 16-byte header on the 64-bit heap, 8 bytes on the 31-bit
 * heap, with the low-order word of the length immediately before the user
 * pointer in both. IBM does not document this, and the options above change
 * it, so the header is read only when LE says the heap is stock. Even then
 * the value is checked for the shape a stock element must have.
 */

#ifdef _LP64
#define LE_HEAP_ELEMENT_OVERHEAD 0x10
#else
#define LE_HEAP_ELEMENT_OVERHEAD 0x08
#endif

size_t malloc_usable_size (const void *ptr){
  if (ptr == NULL || isLEHeapCheckActive()) {
    return 0;
  }
  unsigned int elementLength = *(const unsigned int *)((const char *)ptr - 4);
  if (elementLength < LE_HEAP_ELEMENT_OVERHEAD || (elementLength & 7) != 0) {
    return 0;                                     /* not a stock element header */
  }
  return elementLength - LE_HEAP_ELEMENT_OVERHEAD;
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

#if defined(__XPLINK__)
int32_t atomicIncrementI32(int32_t *place, int32_t increment){
  int32_t oldValue = 0;
  int32_t newValue = 0;  /* just to let compiler figure out a register */
  int pswMask = 0;
#ifdef _LP64
  int64_t addr = (int64_t)place;
#else 
  int32_t addr = (int32_t)place;
#endif
  while (1){
    oldValue = *place;
    newValue = oldValue+increment;
    /* printf("old=%d new=%d\n",oldValue,newValue); */
    __asm("         L  9,%0   \n"
          "         L  10,%1   \n"
	  "         LG 11,%2  \n"
	  "         CS 9,10,0(11) \n"
	  "         EPSW 10,0 note re-use of r10 \n"
	  "         ST 10,%3 "
	  :
	  :
	  "m"(oldValue),"m"(newValue),"m"(addr),"m"(pswMask)
	  :
	  "r9","r10","r11");
    int cc = 0x3000 & pswMask;
    /* printf("pswMask=0x%08X, old=%d\n",pswMask,oldValue); */
    if (cc == 0){ /* Pseudo JZ out of loop */
      break;
    }
  }
  return oldValue;
}

#else 

int32_t atomicIncrementI32(int32_t *place, int32_t increment){
  int old = *place;
  /* printf("Ay caramba\n"); */
  *place = (old + increment);
  return old;
}

#endif


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

/* ADD */
int atomicAddInt(int *p, int x){
  int old = *p;
  *p = old+x;
  return old;
}

uint64_t atomicAddU64(_Atomic(uint64_t) *p, uint64_t x){
  uint64_t old = *p;
  *p = old+x;
  return old;
}

uint32_t atomicAddU32(_Atomic(uint32_t) *p, uint32_t x){
  uint32_t old = *p;
  *p = old+x;
  return old;
}

uint16_t atomicAddU16(_Atomic(uint16_t) *p, uint16_t x){
  uint16_t old = *p;
  *p = old+x;
  return old;
}

uint8_t atomicAddU8(_Atomic(uint8_t) *p, uint8_t x){
  uint8_t old = *p;
  *p = old+x;
  return old;
}

/* SUB */
int atomicSubInt(int *p, int x){
  int old = *p;
  *p = old-x;
  return old;
}

uint64_t atomicSubU64(_Atomic(uint64_t) *p, uint64_t x){
  uint64_t old = *p;
  *p = old-x;
  return old;
}

uint32_t atomicSubU32(_Atomic(uint32_t) *p, uint32_t x){
  uint32_t old = *p;
  *p = old-x;
  return old;
}

uint16_t atomicSubU16(_Atomic(uint16_t) *p, uint16_t x){
  uint16_t old = *p;
  *p = old-x;
  return old;
}

uint8_t atomicSubU8(_Atomic(uint8_t) *p, uint8_t x){
  uint8_t old = *p;
  *p = old-x;
  return old;
}

/* AND */
int atomicAndInt(int *p, int x){
  int old = *p;
  *p = old & x;
  return old;
}

uint64_t atomicAndU64(_Atomic(uint64_t) *p, uint64_t x){
  uint64_t old = *p;
  *p = old & x;
  return old;
}

uint32_t atomicAndU32(_Atomic(uint32_t) *p, uint32_t x){
  uint32_t old = *p;
  *p = old & x;
  return old;
}

uint16_t atomicAndU16(_Atomic(uint16_t) *p, uint16_t x){
  uint16_t old = *p;
  *p = old & x;
  return old;
}

uint8_t atomicAndU8(_Atomic(uint8_t) *p, uint8_t x){
  uint8_t old = *p;
  *p = old & x;
  return old;
}

/* OR */
int atomicOrInt(int *p, int x){
  int old = *p;
  *p = old | x;
  return old;
}

uint64_t atomicOrU64(_Atomic(uint64_t) *p, uint64_t x){
  uint64_t old = *p;
  *p = old | x;
  return old;
}

uint32_t atomicOrU32(_Atomic(uint32_t) *p, uint32_t x){
  uint32_t old = *p;
  *p = old | x;
  return old;
}

uint16_t atomicOrU16(_Atomic(uint16_t) *p, uint16_t x){
  uint16_t old = *p;
  *p = old | x;
  return old;
}

uint8_t atomicOrU8(_Atomic(uint8_t) *p, uint8_t x){
  uint8_t old = *p;
  *p = old | x;
  return old;
}

/* XOR */
int atomicXorInt(int *p, int x){
  int old = *p;
  *p = old ^ x;
  return old;
}

uint64_t atomicXorU64(_Atomic(uint64_t) *p, uint64_t x){
  uint64_t old = *p;
  *p = old ^ x;
  return old;
}

uint32_t atomicXorU32(_Atomic(uint32_t) *p, uint32_t x){
  uint32_t old = *p;
  *p = old ^ x;
  return old;
}

uint16_t atomicXorU16(_Atomic(uint16_t) *p, uint16_t x){
  uint16_t old = *p;
  *p = old ^ x;
  return old;
}

uint8_t atomicXorU8(_Atomic(uint8_t) *p, uint8_t x){
  uint8_t old = *p;
  *p = old ^ x;
  return old;
}

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
int atomicExchangeInt(int *p, int x){
  int old = *p;
  *p = x;
  return old;
}

uint64_t atomicExchangeU64(_Atomic(uint64_t) *p, uint64_t x){
  uint64_t old = *p;
  *p = x;
  return old;
}

uint32_t atomicExchangeU32(_Atomic(uint32_t) *p, uint32_t x){
  uint32_t old = *p;
  *p = x;
  return old;
}

uint16_t atomicExchangeU16(_Atomic(uint16_t) *p, uint16_t x){
  uint16_t old = *p;
  *p = x;
  return old;
}

uint8_t atomicExchangeU8(_Atomic(uint8_t) *p, uint8_t x){
  uint8_t old = *p;
  *p = x;
  return old;
}

/* Compare_Exchange_Strong */
_Bool atomicCompareExchangeStrongInt(int *p, int *exp, int desired){
  if (*p == *exp){
    *p = desired;
    return true;
  } else{
    *exp = *p;
    return false;
  } 
}

_Bool atomicCompareExchangeStrongU64(_Atomic(uint64_t) *p, uint64_t *exp, uint64_t desired){
  if (*p == *exp){
    *p = desired;
    return true;
  } else{
    *exp = *p;
    return false;
  } 
}

_Bool atomicCompareExchangeStrongU32(_Atomic(uint32_t) *p, uint32_t *exp, uint32_t desired){
  if (*p == *exp){
    *p = desired;
    return true;
  } else{
    *exp = *p;
    return false;
  } 
}

_Bool atomicCompareExchangeStrongU16(_Atomic(uint16_t) *p, uint16_t *exp, uint16_t desired){
  if (*p == *exp){
    *p = desired;
    return true;
  } else{
    *exp = *p;
    return false;
  } 
}

_Bool atomicCompareExchangeStrongU8(_Atomic(uint8_t) *p, uint8_t *exp, uint8_t desired){
  if (*p == *exp){
    *p = desired;
    return true;
  } else{
    *exp = *p;
    return false;
  } 
}


