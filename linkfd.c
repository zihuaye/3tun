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
 * $Id: linkfd.c,v 1.13.2.3 2008/01/07 22:35:43 mtbishop Exp $
 */

#include "config.h"
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <pthread.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "driver.h"

/* used by lfd_encrypt */
int send_a_packet = 0;

int merge_2 = 1;
int merge_3 = 0;

int legacy_tunnel = 1;
int force_legacy = 0;

int tv_us = 0;

int threading_mode = 0;

struct thread_args {
	int rl;
	int *p;
};

extern  pthread_mutex_t dev_lock, proto_lock;

/* Host we are working with. 
 * Used by signal handlers that's why it is global. 
 */
struct vtun_host *lfd_host;

struct lfd_mod *lfd_mod_head = NULL, *lfd_mod_tail = NULL;

/* Modules functions*/

/* Add module to the end of modules list */
void lfd_add_mod(struct lfd_mod *mod)
{
     if( !lfd_mod_head ){
        lfd_mod_head = lfd_mod_tail = mod;
	mod->next = mod->prev = NULL;
     } else {
        lfd_mod_tail->next = mod;
        mod->prev = lfd_mod_tail;
        mod->next = NULL;
        lfd_mod_tail = mod;
     }
}

/*  Initialize and allocate each module */
int lfd_alloc_mod(struct vtun_host *host)
{
     struct lfd_mod *mod = lfd_mod_head;

     while( mod ){
        if( mod->alloc && (mod->alloc)(host) )
	   return 1; 
	mod = mod->next;
     } 

     return 0;
}

/* Free all modules */
int lfd_free_mod(void)
{
     struct lfd_mod *mod = lfd_mod_head;

     while( mod ){
        if( mod->free && (mod->free)() )
	   return 1;
	mod = mod->next;
     } 
     lfd_mod_head = lfd_mod_tail = NULL;
     return 0;
}

 /* Run modules down (from head to tail) */
#if defined(__mips__)
int lfd_run_down(int len, char *in, char **out)
#else
inline int lfd_run_down(int len, char *in, char **out)
#endif
{
     register struct lfd_mod *mod;
     
     *out = in;
     for(mod = lfd_mod_head; mod && len > 0; mod = mod->next )
        if( mod->encode ){
           len = (mod->encode)(len, in, out);
           in = *out;
        }
     return len;
}

/* Run modules up (from tail to head) */
#if defined(__mips__)
int lfd_run_up(int len, char *in, char **out)
#else
inline int lfd_run_up(int len, char *in, char **out)
#endif
{
     register struct lfd_mod *mod;
     
     *out = in;
     for(mod = lfd_mod_tail; mod && len > 0; mod = mod->prev )
        if( mod->decode ){
	   len = (mod->decode)(len, in, out);
           in = *out;
	}
     return len;
}

/* Check if modules are accepting the data(down) */
#if defined(__mips__)
int lfd_check_down(void)
#else
inline int lfd_check_down(void)
#endif
{
     register struct lfd_mod *mod;
     int err = 1;
 
     for(mod = lfd_mod_head; mod && err > 0; mod = mod->next )
        if( mod->avail_encode )
           err = (mod->avail_encode)();
     return err;
}

/* Check if modules are accepting the data(up) */
#if defined(__mips__)
int lfd_check_up(void)
#else
inline int lfd_check_up(void)
#endif
{
     register struct lfd_mod *mod;
     int err = 1;

     for(mod = lfd_mod_tail; mod && err > 0; mod = mod->prev)
        if( mod->avail_decode )
           err = (mod->avail_decode)();

     return err;
}
		
/********** Linker *************/
/* Termination flag */
static volatile sig_atomic_t linker_term;

static void sig_term(int sig)
{
     vtun_syslog(LOG_INFO, "Closing connection");
     io_cancel();
     linker_term = VTUN_SIG_TERM;
}

static void sig_hup(int sig)
{
     vtun_syslog(LOG_INFO, "Reestablishing connection");
     io_cancel();
     linker_term = VTUN_SIG_HUP;
}

/* Statistic dump */
void sig_alarm(int sig)
{
     static time_t tm;
     static char stm[20];
  
     tm = time(NULL);
     strftime(stm, sizeof(stm)-1, "%b %d %H:%M:%S", localtime(&tm)); 
     fprintf(lfd_host->stat.file,"%s %lu %lu %lu %lu\n", stm, 
	lfd_host->stat.byte_in, lfd_host->stat.byte_out,
	lfd_host->stat.comp_in, lfd_host->stat.comp_out); 
     
     alarm(VTUN_STAT_IVAL);
}    

static void sig_usr1(int sig)
{
     /* Reset statistic counters on SIGUSR1 */
     lfd_host->stat.byte_in = lfd_host->stat.byte_out = 0;
     lfd_host->stat.comp_in = lfd_host->stat.comp_out = 0; 
}

int lfd_linker(struct thread_args *pt)
{
     int fd1 = lfd_host->rmt_fd;
     int fd2 = lfd_host->loc_fd; 
     register int len, fl, len0, len2, len3;
     struct timeval tv, tv2;
     char *buf, *out, *pb, *pb2, *pb3;
     fd_set fdset, fdset2;
     int maxfd, idle = 0, tmplen, p, log_merge = 1, log_tunnel = 1;
     unsigned short *pi, mask, echo_req;
     int t0=1, t1=1, t2=1, t1_exit_call=0, t2_exit_call=0;

     if (pt != NULL) {
     	/* threading init */
	t0 = 0;

	if (pt->rl == 1) {
		//remote proto thread
		t2 = 0;
	} else if (pt->rl == 2) {
		//local dev thread
		t1 = 0;
	}

	vtun_syslog(LOG_INFO, "lfd_linker() t0:%d t1:%d t2:%d p[0]:%d p[1]:%d p[2]:%d p[3]:%d",
			t0, t1, t2, pt->p[0], pt->p[1], pt->p[2], pt->p[3]); 
     }

     if( !(buf = lfd_alloc((VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD)*2)) ){
	vtun_syslog(LOG_ERR,"Can't allocate buffer for the linker"); 
        return 0; 
     }

     tv_us = 0;

     /* reset tunnel mode */
     legacy_tunnel = 1;
     mask = VTUN_FSIZE_MASK0;

     echo_req = (force_legacy ? VTUN_ECHO_REQ : VTUN_ECHO_REQ2);

     /* VTUN_ECHO_REQ2: identify self as a new format tunnel,
 	legacy tunnel will just recognize it as VTUN_ECHO_REQ */
     if (t1)
	/* t1==1: remote proto thread */
     	proto_write(fd1, buf, echo_req);

     if (t0)
	/* none thread */
     	maxfd = (fd1 > fd2 ? fd1 : fd2) + 1;

     linker_term = 0;
     while( !linker_term ){
	errno = 0;

        /* Wait for data */
        FD_ZERO(&fdset);
	if (t0) {
		FD_SET(fd1, &fdset);
		FD_SET(fd2, &fdset);
	} else {
		if (t1) {
			//select remote fd1 and t1_read
			FD_SET(fd1, &fdset);
			FD_SET(pt->p[0], &fdset);
     			maxfd = (fd1 > pt->p[0] ? fd1 : pt->p[0]) + 1;
		}
		if (t2) {
			//select local dev fd2 and t2_read
			FD_SET(fd2, &fdset);
			FD_SET(pt->p[2], &fdset);
     			maxfd = (fd2 > pt->p[2] ? fd2 : pt->p[2]) + 1;
		}
	}

 	tv.tv_sec  = lfd_host->ka_interval;
	tv.tv_usec = 0;

	if( (len = select(maxfd, &fdset, NULL, NULL, &tv)) < 0 ){
	   if( errno != EAGAIN && errno != EINTR )
	      break;
	   else
	      continue;
	} 
	if (send_a_packet&&t2)
        {
           send_a_packet = 0;
           tmplen = 1;
	   lfd_host->stat.byte_out += tmplen; 
	   if( (tmplen=lfd_run_down(tmplen,buf,&out)) == -1 )
	      break;
	   if( tmplen && proto_write(fd1, out, tmplen) < 0 )
	      break;
	   lfd_host->stat.comp_out += tmplen; 
        }
	if( (!len)&&t1 ){
	   /* We are idle, lets check connection */
	   if( lfd_host->flags & VTUN_KEEP_ALIVE ){
	      if( ++idle > lfd_host->ka_failure ){
	         vtun_syslog(LOG_INFO,"Session %s network timeout", lfd_host->host);
		 break;	
	      }
	      /* Send ECHO request */
	      if( proto_write(fd1, buf, echo_req) < 0 )
		 break;
	   }
	   continue;
	}	   

	/* Read frames from network(fd1), decode and pass them to 
         * the local device (fd2) */
	if( t1 && FD_ISSET(fd1, &fdset) && lfd_check_up() ){
	   idle = 0; 
	   if( (len=proto_read(fd1, buf)) <= 0 )
	      break;

	   /* Handle frame flags */
	   fl = len & ~mask;
           len = len & mask;
	   if( fl ){
	    	if( fl==VTUN_BAD_FRAME ){
	 		vtun_syslog(LOG_ERR, "Received bad frame");
	 		continue;
	  	}
	      	if( fl==VTUN_ECHO_REQ ){
			if ((len > 0)&&(!force_legacy)) {
				/* recieved VTUN_ECHO_REQ2, peer tunnel format is a new one */
				legacy_tunnel = 0;
	   			mask = VTUN_FSIZE_MASK;

				if (log_tunnel) {
	         			vtun_syslog(LOG_INFO,"%s: Peer has a new tunnel format",
							lfd_host->host);
					log_tunnel -= 1;
				}
			}

			/* Send ECHO reply */
	 	 	if( proto_write(fd1, buf, VTUN_ECHO_REP) < 0 )
		    		break;
		 	continue;
	      	}
   	      	if( fl==VTUN_ECHO_REP ){
			/* Just ignore ECHO reply */
		 	continue;
	      	}
	      	if( (fl==VTUN_CONN_CLOSE)||(fl==VTUN_CONN_CLOSE0) ){
	         	vtun_syslog(LOG_INFO,"Connection closed by other side");
		 	break;
	      	}
	   }   

	   lfd_host->stat.comp_in += len; 
	   if( (len=lfd_run_up(len,buf,&out)) == -1 )
	    	break;	

	   if (legacy_tunnel) {

		/* old format tunnel code */

	   	if( len && dev_write(fd2,out,len) < 0 ){
              		if( errno != EAGAIN && errno != EINTR )
                 		break;
              		else
                 		continue;
           	}
	   	lfd_host->stat.byte_in += len; 

	   } else {

	   	/* new impovement tunnle code begin */

	   	pb = out + len - sizeof(short);
	   	pi = (unsigned short *)pb;

	   	len0 = len;  		//total pkt size
	   	len = ntohs(*pi); 	//first pkt size

	   	if (len > 0) {
	      		//2 or 3 pkts contained 
	      		pb = out;
	      		p = 0;

	      		while ( p < 3 ) {
				p += 1;

	   			if( len && dev_write(fd2,pb,len) < 0 ){
              				if( errno != EAGAIN && errno != EINTR )
                 				break;
              				else
                 				continue;
           			}
				lfd_host->stat.byte_in += len; 

				len0 -= len + sizeof(short);

				if (len0 > 0) {
					pb += len;
					pi = (unsigned short *)pb;
					len = ntohs(*pi);  		//next pkt size 
					pb += sizeof(short);
				} else {
					break;
				}
	      		}
	   	} else {
			//only 1 pkt
	   		if( len0 && dev_write(fd2,out,len0-sizeof(short)) < 0 ){
              			if( errno != EAGAIN && errno != EINTR )
                 			break;
              			else
                 			continue;
           		}
	   		lfd_host->stat.byte_in += len0; 
	   	}

	   	/* new impovement tunnel code end */
	   }
	}

	/* Read data from the local device(fd2), encode and pass it to 
         * the network (fd1) */
	if( t2 && FD_ISSET(fd2, &fdset) && lfd_check_down() ){
	   if( (len = dev_read(fd2, buf, VTUN_FRAME_SIZE)) < 0 ){
	   	if( errno != EAGAIN && errno != EINTR )
	       		break;
	      	else
	 		continue;
	   }
	   if( !len ) break;
	
	   if (legacy_tunnel) {

		/* old format tunnel code */

	   	lfd_host->stat.byte_out += len; 
	   	if( (len=lfd_run_down(len,buf,&out)) == -1 )
	      		break;
	   	if( len && proto_write(fd1, out, len) < 0 )
	      		break;
	   	lfd_host->stat.comp_out += len; 
		continue;
	   }

	   /* new impovement tunnel code begin */

	   /* move buffer pointer to next data area */
	   pb  = buf + len;
	   pi  = (unsigned short *)pb;
	   *pi = htons(0);
	   pb += sizeof(short);

	   if ((len > VTUN_PACKET_TINY_SIZE)&&(len < VTUN_FRAME_SIZE/2)&&(merge_2 == 1)) {
		/* pkt too small, try merge */
        	FD_ZERO(&fdset2);
		FD_SET(fd2, &fdset2);

 		tv2.tv_sec  = 0;
		tv2.tv_usec = tv_us;	// tv_us:0 means non-blocking select

		if ( select(fd2+1, &fdset2, NULL, NULL, &tv2) > 0 ) {

			if(FD_ISSET(fd2, &fdset2)&&lfd_check_down())
				len2 = dev_read(fd2, pb, VTUN_FRAME_SIZE);

			if (log_merge > 0) {
				vtun_syslog(LOG_INFO,"%s: 2 package merge active", lfd_host->host);
				log_merge -= 1;
			}

			if ( len+len2 < VTUN_FRAME_SIZE - VTUN_FRAME_OVERHEAD ) {
				if ((len+len2 >= VTUN_FRAME_SIZE/2)||(merge_3 == 0)) {
					/* merge 2 packets in one to send */
					*pi = htons(len2);
					pb += len2;
					pi  = (unsigned short *)pb;
					*pi = htons(len);

					send_n(fd1, buf, out, len+len2+2*sizeof(short));
				} else {
					/* buf not 50% full yet, try merge 3 packets 1 one to send */
        				FD_ZERO(&fdset2);
					FD_SET(fd2, &fdset2);

 					tv2.tv_sec  = 0;
					tv2.tv_usec = tv_us;

					if ( select(fd2+1, &fdset2, NULL, NULL, &tv2) > 0 ) {

						*pi = htons(len2);
						pb += len2;
						pi  = (unsigned short *)pb;
						*pi = htons(len);
	   					pb += sizeof(short);

						if(FD_ISSET(fd2, &fdset2)&&lfd_check_down())
							len3 = dev_read(fd2, pb, VTUN_FRAME_SIZE);

						if (log_merge > -1) {
							vtun_syslog(LOG_INFO,"%s: 3 package merge active",
									lfd_host->host);
							log_merge -= 1;
						}

						if ( len+len2+len3 < VTUN_FRAME_SIZE - VTUN_FRAME_OVERHEAD ) {
							//it's ok to merge 3 in 1
							*pi = htons(len3);
							pb += len3;
							pi  = (unsigned short *)pb;
							*pi = htons(len);
	   						pb += sizeof(short);

							send_n(fd1, buf, out, len+len2+len3+3*sizeof(short));
						} else {
							//over frame size, send first 2, then last 1
							send_n(fd1, buf, out, len+len2+2*sizeof(short));

							pb3 = pb + len3;
							pi = (unsigned short *)pb3;
							*pi = htons(0);

							send_n(fd1, pb, out, len3+sizeof(short));
						}
					} else {
						//only 2 pkts avalible
						*pi = htons(len2);
						pb += len2;
						pi = (unsigned short *)pb;
						*pi = htons(len);

						send_n(fd1, buf, out, len+len2+2*sizeof(short));
					}
				}
			} else {
				// pkt1+pkt2 size >= VTUN_FRAME_SIZE-VTUN_FRAME_OVERHEAD, send pkts one by one
				send_n(fd1, buf, out, len+sizeof(short));

				pb2 = pb + len2;
				pi  = (unsigned short *)pb2;
				*pi = htons(0);

				send_n(fd1, pb, out, len2+sizeof(short));
			}
		} else {
			// no more pkt avalible
			send_n(fd1, buf, out, len+sizeof(short));
		}
	   } else {
		// pkt size >= VTUN_FRAME_SIZE/2, or too tiny, or merge_2 off, send it at once
		send_n(fd1, buf, out, len+sizeof(short));
	   }

	   /* new impovement tunnel code end */

	}


	if( (!t0) && t1 && FD_ISSET(pt->p[0], &fdset) ){
		if (read(pt->p[0], buf, 8) > 0) {
			t2_exit_call = 1;
			break;
		}
	}

	if( (!t0) && t2 && FD_ISSET(pt->p[2], &fdset) ){
		if (read(pt->p[2], buf, 8) > 0) {
			t1_exit_call = 1;
			break;
		}
	}

     }
     if( !linker_term && errno )
	vtun_syslog(LOG_INFO,"%s (%d)", strerror(errno), errno);

     if (linker_term == VTUN_SIG_TERM) {
       lfd_host->persist = 0;
     }

     if (t1) {
     	/* Notify other end about our close */
     	proto_write(fd1, buf, (legacy_tunnel ? VTUN_CONN_CLOSE0 : VTUN_CONN_CLOSE));

     	if ((!t0)&&(!t2_exit_call)&&(!linker_term))  //call t2 to exit
	  write(pt->p[3], "VT exit\0", 8);
     }

     if (t2&&(!t0)&&(!t1_exit_call)&&(!linker_term)) { //call t1 to exit
	write(pt->p[1], "VT exit\0", 8);
     }

     lfd_free(buf);

     return 0;
}

#if defined(__mips__)
int send_n(int fd, char *in, char *out, int n)
#else
inline int send_n(int fd, char *in, char *out, int n)
#endif
{
     int len = 0;

     lfd_host->stat.byte_out += n; 
     if ((len = lfd_run_down(n, in, &out)) > 0)
     	if ((len = proto_write(fd, out, len)) > 0)
     		lfd_host->stat.comp_out += len;

     return len;
}

/* Link remote and local file descriptors */ 
int linkfd(struct vtun_host *host)
{
     struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup;
     int old_prio;

     pthread_t tid[2];
     struct thread_args t_args_1, t_args_2;
     int p[4];
     enum{
	t1_read  = 0, //read end for proto
	t2_write = 1, //write end for dev 
	t2_read  = 2, //read end for dev 
	t1_write = 3  //write end for proto
     };

     lfd_host = host;
 
     old_prio=getpriority(PRIO_PROCESS,0);
     setpriority(PRIO_PROCESS,0,LINKFD_PRIO);

     /* Build modules stack */
     if(host->flags & VTUN_ZLIB)
	lfd_add_mod(&lfd_zlib);

     if(host->flags & VTUN_LZO)
	lfd_add_mod(&lfd_lzo);

     if(host->flags & VTUN_ENCRYPT)
       if(host->cipher == VTUN_LEGACY_ENCRYPT) {
	 lfd_add_mod(&lfd_legacy_encrypt);
       } else {
	 lfd_add_mod(&lfd_encrypt);
       }
     
     if(host->flags & VTUN_SHAPE)
	lfd_add_mod(&lfd_shaper);

     if(lfd_alloc_mod(host))
	return 0;

     memset(&sa, 0, sizeof(sa));
     sa.sa_handler=sig_term;
     sigaction(SIGTERM,&sa,&sa_oldterm);
     sigaction(SIGINT,&sa,&sa_oldint);
     sa.sa_handler=sig_hup;
     sigaction(SIGHUP,&sa,&sa_oldhup);

     /* Initialize statstic dumps */
     if( host->flags & VTUN_STAT ){
	char file[40];

        sa.sa_handler=sig_alarm;
        sigaction(SIGALRM,&sa,NULL);
        sa.sa_handler=sig_usr1;
        sigaction(SIGUSR1,&sa,NULL);

	sprintf(file,"%s/%.20s", VTUN_STAT_DIR, host->host);
	if( (host->stat.file=fopen(file, "a")) ){
	   setvbuf(host->stat.file, NULL, _IOLBF, 0);
	   alarm(VTUN_STAT_IVAL);
	} else
	   vtun_syslog(LOG_ERR, "Can't open stats file %s", file);
     }

     io_init();

     if (!threading_mode) {

     	lfd_linker(NULL);

     } else {

	if (pipe(&p[t1_read]) == -1 || (pipe(&p[t2_read]) == -1))
	  return linker_term;

	if ((pthread_mutex_init(&dev_lock, NULL) != 0)||(pthread_mutex_init(&proto_lock, NULL) != 0))
	  return linker_term;

	t_args_1.rl = 1;
	t_args_1.p = p;
	t_args_2.rl = 2;
	t_args_2.p = p;

	pthread_create(&(tid[0]), NULL, &lfd_linker, &t_args_1);
	pthread_create(&(tid[1]), NULL, &lfd_linker, &t_args_2);

	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);

	pthread_mutex_destroy(&dev_lock);
	pthread_mutex_destroy(&proto_lock);

     }

     if( host->flags & VTUN_STAT ){
        alarm(0);
	if (host->stat.file)
	  fclose(host->stat.file);
     }

     lfd_free_mod();
     
     sigaction(SIGTERM,&sa_oldterm,NULL);
     sigaction(SIGINT,&sa_oldint,NULL);
     sigaction(SIGHUP,&sa_oldhup,NULL);

     setpriority(PRIO_PROCESS,0,old_prio);

     return linker_term;
}
