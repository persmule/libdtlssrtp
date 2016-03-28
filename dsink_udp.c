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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "dsink_udp.h"
/*
 * An exemplative data sink implemented directory atop sendto(2),
 * with no scheduling ability.
 */
static DSINK_SENDTO(udp_sendto)
{
  return sendto(
		(fd_t)carrier,
		data,
		datalen,
		flags,
		(const struct sockaddr*)target,
		(socklen_t)tglen
		);
}

static const dsink dsink_udp = {
  "dsink_udp",
  udp_sendto,
  NULL,
};

const dsink* dsink_udp_getsink(void)
{
  return &dsink_udp;
}

