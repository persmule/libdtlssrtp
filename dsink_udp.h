#ifndef _DSINK_UDP_H
#define _DSINK_UDP_H

#include "data_sink.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int fd_t;

const dsink* dsink_udp_getsink(void);

#ifdef __cplusplus
}
#endif

#endif
