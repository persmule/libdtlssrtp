#ifndef _DATA_SINK_H_
#define _DATA_SINK_H_

#include <stddef.h>
#include <sys/time.h> //for struct timeval

#ifdef __cplusplus
extern "C" {
#endif

#define DSINK_SENDTO(x)				\
  ptrdiff_t (x)					\
  (void* carrier,				\
   const void* data,				\
   size_t datalen,				\
   int flags,					\
   const void* target,				\
   int tglen)					\

typedef DSINK_SENDTO(dsink_sendto);

  /*
   * Used to schedule timeout handling,
   * timer functionality is supposed to
   * implemented optionally within *carrier, 
   * with scheduling state stored, tv could
   * be NULL to indicate NO new timeout 
   * handling is scheduled.
   */ 
#define DSINK_TIMER_SCHED(x)			\
  void (x)(void* carrier,			\
	  const struct timeval* tv)		\

typedef DSINK_TIMER_SCHED(dsink_timer_sched);
  
typedef struct dsink{
  const char* name;
  dsink_sendto* sendto;
  dsink_timer_sched* sched;
}dsink;

#ifdef __cplusplus
}
#endif
       
#endif
