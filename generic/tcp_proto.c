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
 * $Id: tcp_proto.c,v 1.7.2.2 2008/01/07 22:36:16 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <pthread.h>

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
#include <netinet/tcp.h>
#endif

#include "vtun.h"
#include "lib.h"

extern int legacy_tunnel;
extern int threading_mode;

pthread_rwlock_t proto_lock;

int tcp_write(int fd, char *buf, int len)
{
     register char *ptr;
     unsigned short mask, plen, n;

     ptr = buf - sizeof(short);			//first 2 bytes is frame size
     *((unsigned short *)ptr) = htons(len); 	//converts host byte order to network byte order

     mask = (legacy_tunnel ? VTUN_FSIZE_MASK0 : VTUN_FSIZE_MASK);
     plen = (len >= VTUN_ECHO_REQ ? sizeof(short) : (len & mask) + sizeof(short));

     if (threading_mode) {
	pthread_rwlock_wrlock(&proto_lock);
     	n = write_n(fd, ptr, plen);
	pthread_rwlock_unlock(&proto_lock);
     	return n;
     } else {
     	return write_n(fd, ptr, plen);
     }
}

int tcp_read(int fd, char *buf)
{
     unsigned short len, flen, mask, n;
     register int rlen;

     if (threading_mode)
	pthread_rwlock_rdlock(&proto_lock);

     /* Read frame size */
     if( (rlen = read_n(fd, (char *)&len, sizeof(short)) ) <= 0)
	return rlen;

     len = ntohs(len);		//converts network byte order to host byte order

     mask = (legacy_tunnel ? VTUN_FSIZE_MASK0 : VTUN_FSIZE_MASK);
     flen = (len >= VTUN_ECHO_REQ ? 0 : len & mask);

     if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ){
     	/* Oversized frame, drop it. */ 
        while( flen ){
	   len = min(flen, VTUN_FRAME_SIZE);
           if( (rlen = read_n(fd, buf, len)) <= 0 )
	      break;
           flen -= rlen;
        }                                                               
	return VTUN_BAD_FRAME;
     }	

     if( len & ~mask ){
	/* Return flags, without data */
     	if (threading_mode)
		pthread_rwlock_unlock(&proto_lock);
	return len;
     }

     /* Read frame */
     n = read_n(fd, buf, flen);

     if (threading_mode)
	pthread_rwlock_unlock(&proto_lock);

     return n;
}
