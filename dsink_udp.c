#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "dsink_udp.h"

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

