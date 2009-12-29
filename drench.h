/*
 * drench, a connection exhaustion test tool
 *
 * Copyright (c) 2005-2007 Michael Santos/michael.santos@gmail.com
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

