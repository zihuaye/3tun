/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2008  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * $Id: udp_proto.c,v 1.10.2.2 2008/01/07 22:36:19 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/udp.h>
#endif

#include "vtun.h"
#include "lib.h"

extern int legacy_tunnel;

/* Functions to read/write UDP frames. */
int udp_write(int fd, char *buf, int len)
{
     register char *ptr;
     register int wlen;

     ptr = buf - sizeof(short);

     if (legacy_tunnel) {
        if (len == VTUN_CONN_CLOSE) {
                len = 0x1000;
        }
     }

     *((unsigned short *)ptr) = htons(len); 

     if (legacy_tunnel) {
     	len  = (len & 0x0fff) + sizeof(short);
     } else {
     	len  = (len & VTUN_FSIZE_MASK) + sizeof(short);
     }


     while( 1 ){
	if( (wlen = write(fd, ptr, len)) < 0 ){ 
	   if( errno == EAGAIN || errno == EINTR )
	      continue;
	   if( errno == ENOBUFS )
	      return 0;
	}
	/* Even if we wrote only part of the frame
         * we can't use second write since it will produce 
         * another UDP frame */  
        return wlen;
     }
}

int udp_read(int fd, char *buf)
{
     unsigned short hdr, flen;
     struct iovec iv[2];
     register int rlen;

     /* Read frame */
     iv[0].iov_len  = sizeof(short);
     iv[0].iov_base = (char *) &hdr;
     iv[1].iov_len  = VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD;
     iv[1].iov_base = buf;

     while( 1 ){
        if( (rlen = readv(fd, iv, 2)) < 0 ){ 
	   if( errno == EAGAIN || errno == EINTR )
	      continue;
	   else
     	      return rlen;
	}
        hdr = ntohs(hdr);
     	if (legacy_tunnel) {
        	if (hdr == 0x1000) {
                	hdr = VTUN_CONN_CLOSE;
        	}
     	}
        flen = hdr & VTUN_FSIZE_MASK;

        if( rlen < 2 || (rlen-2) != flen )
	   return VTUN_BAD_FRAME;

	return hdr;
     }
}		
