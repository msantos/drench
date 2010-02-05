/* Copyright (c) 2005-2010, Michael Santos <michael.santos@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * drench, a connection exhaustion test tool
 *
 * Stateless TCP connection flood
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include <pcap.h>
//#include <dnet.h> 

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <libnet.h>

#define DRENCH_BUILD   "0.3"

#define PCAP_ERRBUF(x) do { \
    if ((x) == NULL) \
        errx(EXIT_FAILURE, "%s: %s", #x, errbuf); \
} while (0);

#define PCAP_ERR(x) do { \
    if ((x) != 0) \
        errx(EXIT_FAILURE, "%s: %s", #x, pcap_geterr(p)); \
} while (0);

#define LIBNET_ERR(x) do { \
    if ((x) == -1) { \
        libnet_destroy(dp->l); \
            errx(EXIT_FAILURE, "%s: %s", #x, libnet_geterror(dp->l)); \
    } \
} while (0);

#define ISNULL(x) do { \
    if ((x) == NULL) {\
        (void)fprintf(stderr, "%s", #x); \
            return (1); \
    } \
} while (0)

#define ISZERO(x) do { \
    if ((x) == 0) {\
        (void)fprintf(stderr, "%s", #x); \
            return (1); \
    } \
} while (0)

#define LTZERO(x) do { \
    if ((x) < 0) {\
        (void)fprintf(stderr, "%s", #x); \
            return (1); \
    } \
} while (0)

#define ISSET(x, y) do { \
    if (th->th_flags & x) {\
        (void)fprintf(stdout, "%s", #y); \
    } \
} while (0)


#define TCP_PHASE(x,y,z) ((x) == TH_SYN ? (y) : (z))

extern char *__progname;

#define SNAPLEN     60
#define PROMISC     1   /* true */
#define TIMEOUT     500 /* ms */
#define PCAP_FILT   "tcp and src %s and src port %u"
#define MAXFILT     256

#define TCP_WINSIZE 32768 /* 0 */
#define MAX_TTL     64

#define PAYLOAD     "GET / HTTP/1.1\nHost: www.example.com\r\n";

typedef struct {
    u_int8_t flags;
    u_int16_t winsize;
    u_int8_t range; /* range of addresses to allocate */
    u_int32_t opts; /* options */
    u_int32_t secret; /* Seed for sequence number */
    char *saddr;
    char *daddr;
    in_port_t dport;
    libnet_ptag_t p_tcp;
    libnet_ptag_t p_ip;
    libnet_t *l;
    char *payload;
} pkt_t ;

enum {
    O_ACK = 1,  /* continue ACK'ing */
    O_REPEAT = 2,  /* repeat the scan */
    O_CHKISN = 4,  /* check if the sequence number in the returned ACK is valid */
};

void drench_writer(pkt_t *dp, u_int32_t count, u_int32_t group, u_int32_t use);
void drench_reader(pkt_t *dp, pcap_t *p);
void drench_cleanup(int sig);

void drench_send_tcp(pkt_t *dp, u_int8_t offset, u_char *pkt);
int create_arp_pool(libnet_t *l, u_int8_t iprange);
int create_arp_pool1(pkt_t *dp);
int destroy_arp_pool1(pkt_t *dp);
void usage(void);

void drench_err(int rv, char *fmt, ...);
void drench_errx(int rv, char *fmt, ...);
void drench_warn(char *fmt, ...);
void drench_warnx(char *fmt, ...);

