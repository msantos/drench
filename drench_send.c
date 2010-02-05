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
#include "drench.h"
#include <openssl/md5.h>

/* Check the ISN returned in the ACK. If isn is
 * 0, create the ISN
 *
 * Return: 0 = passed, -1 = failed
 *
 */
int check_isn(pkt_t *dp, in_port_t port, u_int32_t *isn);

    void
drench_send_tcp(pkt_t *dp, u_int8_t offset, u_char *pkt)
{
    struct ether_header *eh = NULL;
    struct ip *ih = NULL;
    struct tcphdr *th = NULL;

    char *state = NULL;

    in_port_t sport = 0;
    size_t paylen = 0;

    u_int32_t isn = 0;

    if (dp->payload != NULL)
        paylen = strlen(dp->payload);

    state = TCP_PHASE(dp->flags, "S",  "A");

    if (pkt != NULL) {
        eh = (struct ether_header *)pkt;
        ih = (struct ip *)(pkt + sizeof(struct ether_header));
        th = (struct tcphdr *)(pkt + sizeof(struct ether_header) + sizeof(struct ip));

        isn = th->th_ack;
        sport = th->th_dport;

    }
    else {
        sport = libnet_get_prand(LIBNET_PRu16);
    }

    /* Sanity check: check the ack number of the packet to 
     * make sure we sent it. We can do this by performing
     * a calculation on the sequence number we
     * send, based on a "secret" random number */
    if (check_isn(dp, sport, &isn) < 0) {
        (void)fprintf(stdout,
                      "(C->S)[%s] SRC = %15s:%-6u DST = %15s:%-6u INVALID ISN in ACK%s [isn = %u]\n",
                      state,
                      TCP_PHASE(
                          dp->flags,
                          dp->saddr,
                          libnet_addr2name4(ih->ip_dst.s_addr, LIBNET_DONT_RESOLVE)
                          ),
                      sport,
                      TCP_PHASE(
                          dp->flags,
                          dp->daddr,
                          libnet_addr2name4(ih->ip_src.s_addr, LIBNET_DONT_RESOLVE)
                          ),
                      dp->dport,
                      (dp->opts & O_CHKISN ? ", DROPPING PACKET" : ""),
                      isn);

        if (dp->opts & O_CHKISN)
            return;
    }

    LIBNET_ERR(dp->p_tcp = libnet_build_tcp(
                TCP_PHASE(dp->flags, sport, th->th_dport),                                          /* Source port */
                dp->dport,                                                                      /* Destination port */
                TCP_PHASE(dp->flags, isn, (th->th_ack + paylen)),                                   /* ISN */
                /* Sniffed packet's seq num */
                TCP_PHASE(dp->flags, 0, (th->th_seq + 1)),                                          /* ACK */
                TCP_PHASE(dp->flags, dp->flags,  dp->flags /*| TH_PUSH*/),                          /* Control flags */
                dp->winsize,                                                                    /* window size */
                0,                                                                              /* auto checksum */
                0,                                                                              /* Urgent data pointer */
                TCP_PHASE(dp->flags, LIBNET_TCP_H,  LIBNET_TCP_H + paylen),                         /* total packet length */
                TCP_PHASE(dp->flags, NULL, (u_char *)dp->payload),                                  /* payload */
                TCP_PHASE(dp->flags, 0, paylen),                                                    /* payload size */
                dp->l,                                                                          /* libnet context */
                dp->p_tcp                                                                       /* ptag */
                ));

    LIBNET_ERR(dp->p_ip = libnet_build_ipv4(
                TCP_PHASE(dp->flags, LIBNET_IPV4_H + LIBNET_TCP_H, LIBNET_IPV4_H + LIBNET_TCP_H + paylen),
                TCP_PHASE(dp->flags, 0, IPTOS_LOWDELAY),                                            /* TOS */
                libnet_get_prand(LIBNET_PRu16),
                0,                                                                              /* Frag */
                MAX_TTL,                                                                        /* TTL */
                IPPROTO_TCP,                                                                    /* Protocol */
                0,                                                                              /* auto checksum */
                TCP_PHASE(dp->flags, htonl(ntohl(libnet_name2addr4(dp->l, dp->saddr, LIBNET_DONT_RESOLVE)) + offset),
                    ih->ip_dst.s_addr),                                                         /* XXX error check, source */
                TCP_PHASE(dp->flags, libnet_name2addr4(dp->l, dp->daddr, LIBNET_DONT_RESOLVE),
                    ih->ip_src.s_addr),                                                         /* XXX error check, destination */
                NULL,                                                                           /* payload */
                0,                                                                              /* payload size */
                dp->l,                                                                          /* libnet context */
                dp->p_ip                                                                        /* libnet ptag */
                ));

    if (libnet_write(dp->l) == -1)
        state = "x";

    (void)fprintf(stdout, "(C->S)[%s] SRC = %15s:%-6u DST = %15s:%-6u\n", state,
                  TCP_PHASE(
                      dp->flags,
                      libnet_addr2name4(
                          htonl(ntohl(libnet_name2addr4(dp->l, dp->saddr, LIBNET_DONT_RESOLVE)) + offset),
                          LIBNET_DONT_RESOLVE
                          ),
                      libnet_addr2name4(ih->ip_dst.s_addr, LIBNET_DONT_RESOLVE)
                      ),
                  sport,
                  TCP_PHASE(
                      dp->flags,
                      dp->daddr,
                      libnet_addr2name4(ih->ip_src.s_addr, LIBNET_DONT_RESOLVE)
                      ),
                  dp->dport);

    (void)fflush(stdout);
}

    int
check_isn(pkt_t *dp, in_port_t port, u_int32_t *isn)
{
    u_char md5[MD5_DIGEST_LENGTH];
    u_int32_t s = 0;

    struct {
        u_int32_t secret;
        u_int32_t addr;
        in_port_t port;
    } seed;

    (void)memset(&seed, 0, sizeof(seed));

    seed.secret = dp->secret;
    seed.addr = libnet_name2addr4(dp->l, dp->daddr, LIBNET_DONT_RESOLVE);
    seed.port = port;

    (void)MD5((u_char *)&seed, sizeof(seed), md5);
    (void)memcpy(&s, md5, sizeof(s));

    switch (*isn) {
        case 0:
            *isn = htonl(s);
            return (0);
            break;
        default:
            if (*isn == htonl(s+1))
                return (0);
            (void)fprintf(stdout, "\t[ISN RECEIVED = %u, EXPECTING = %u, SECRET = %u, ADDR = %s, PORT = %u]\n",
                          *isn, htonl(s+1), dp->secret, dp->daddr, port);
            /* fall through */
    }

    return (-1);
}
