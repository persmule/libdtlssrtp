#ifndef _DATA_SINK_H_
#define _DATA_SINK_H_

#include <stddef.h>

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

typedef struct dsink{
  const char* name;
  dsink_sendto* sendto;
}dsink;

#ifdef __cplusplus
}
#endif
       
#endif
