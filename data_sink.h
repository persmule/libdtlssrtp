/* Copyright (C) Richfit Information Technology Co.Ltd.
   Contributed by Xie Tianming <persmule@gmail.com>, 2015.

   The DTLS-SRTP library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The DTLS-SRTP library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the DTLS-SRTP library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _DATA_SINK_H_
#define _DATA_SINK_H_
/*
 * An abstract interface to adapt mechanisms able to send packet, 
 * with an optional ability to trigger timeout.
 */
#include <stddef.h>
#include <sys/time.h> //for struct timeval

#ifdef __cplusplus
extern "C" {
#endif
  
  /*
   * A function prototype to send packet, modeled with sendto(2),
   * used to send a packet pointed by 'data', with length 'datalen',
   * to an address opject pointed by 'target', with length 'tglen',
   * via an media object pointed by 'carrier'. If address information
   * is already contained within the *carrier, 'target' and 'tglen' 
   * could be zero and ignored by the implementation of the real send
   * function wrapped with callbacks fit to the prototype.
   */
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
  
  /*
   * Global virtual table structure to represent a specific type of 
   * data sink. A valid data sink is supposed to implement 'sendto',
   * while sched is optional (non-zero), but usually need to be 
   * implemented to perform robust dtls handshake. Unused member must
   * be assigned to zero (NULL) value.
   */
typedef struct dsink{
  const char* name;
  dsink_sendto* sendto;
  dsink_timer_sched* sched;
}dsink;

#ifdef __cplusplus
}
#endif
       
#endif
