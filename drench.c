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

static int drench_exit;

#define DRENCH_EXIT(x, y) do { \
    if (drench_exit == 1) { \
            (void)fprintf(stdout, "[%s] Shutting down %s\n", __progname, x); \
            y; \
    } \
} while (0);


    int
main(int argc, char *argv[])
{    
    pkt_t *dp = NULL;

    int ch = 0;
    u_int32_t count = 5;
    u_int32_t group = 0; /* number of packets to send in group */
    useconds_t usec = 0;    /* rate limit number of SYN's sent */

    pid_t pid = 0;

    /* pcap */
    pcap_t *p = NULL;
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int32_t localnet = 0;
    u_int32_t netmask = 0;
    struct bpf_program fcode;

    char *filt = NULL;

    /* libnet */
    char lerrbuf[LIBNET_ERRBUF_SIZE];

    (void)memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    (void)memset(lerrbuf, 0, LIBNET_ERRBUF_SIZE);

    ISNULL(filt = (char *)calloc(MAXFILT, 1));
    ISNULL(dp = (pkt_t *)calloc(1, sizeof(pkt_t)));

    dp->p_tcp = LIBNET_PTAG_INITIALIZER;
    dp->p_ip = LIBNET_PTAG_INITIALIZER;
    dp->winsize = TCP_WINSIZE;
    dp->opts |= O_CHKISN; /* check the ISN return in the ACK by default */

    drench_exit = 0;    /* global, signal exit from loop */

    while ( (ch = getopt(argc, argv, "ACc:d:hi:p:P:Rr:s:S:x:")) != EOF) {
        switch (ch) {
            case 'A':               /* Continue ACK'ing all ACK's */
                dp->opts |= O_ACK;
                break;
            case 'C':               /* Don't check the returned sequence number in the ACK */
                dp->opts ^= O_CHKISN;
                break;
            case 'c':               /* Number of packets to send */
                count = (u_int32_t)atoi(optarg);
                break;
            case 'd':               /* Destination address */
                dp->daddr = optarg;
                break;
            case 'h':               /* Help */
                usage();
                break;
            case 'i':               /* Use interface */
                dev = optarg;
                break;
            case 'p':               /* Destination port */
                dp->dport = (in_port_t)atoi(optarg);
                break;
            case 'P':
                dp->payload = optarg;   /* Send data with the ACK */
                break;
            case 'r':               /* Range of ip's to allocate */
                dp->range = (u_int8_t)atoi(optarg); 
                break;
            case 'R':               /* Repeat the scan */
                dp->opts |= O_REPEAT;
                break;
            case 's':               /* Source address */
                dp->saddr = strdup(optarg);
                break;
            case 'S':               /* Sleep (microseconds) */
                usec = (useconds_t)atoi(optarg);
                break;
            case 'x':               /* Number of packets to send in group */
                group = (u_int32_t)atoi(optarg);
                break;
            default:
                usage();
                break;
        }
    }


    if (dp->daddr == NULL) {
        (void)fprintf(stderr, "Must specify destination address.\n");
        usage();
    }

    if (dp->dport == 0) {
        (void)fprintf(stderr, "Must specify destination port.\n");
        usage();
    }

    if (dp->range == 0)
        dp->range = 1;

    if (group == 0) 
        group = dp->range;

    if (dev == NULL) 
        PCAP_ERRBUF(dev = pcap_lookupdev(errbuf));

    /* libnet */
    dp->l = libnet_init(LIBNET_RAW4, dev, lerrbuf);

    if (dp->l == NULL)
        errx(EXIT_FAILURE, "libnet_init: %s", lerrbuf);

    if (dp->saddr == NULL) {
        u_int32_t ipaddr = 0;

        /* Assign the inital address. */

        /* FIXME Simplisitically assign the address from
         * FIXME our current address. Note this breaks for many
         * FIXME conditions: if the host is multi-homed, if
         * FIXME another host exists on the network with that IP,
         * FIXME if the final octet rolls past 254, if the network
         * FIXME is classless, IP aliases ...
         *
         * FIXME We can check for these conditions (check the ARP
         * FIXME table, etc), but it is error prone. So just
         * FIXME warn the user and hope for the best.
         */
        if ( (ipaddr = libnet_get_ipaddr4(dp->l)) == -1)
            errx(EXIT_FAILURE, "%s", libnet_geterror(dp->l));

        dp->saddr = strdup(libnet_addr2name4(ipaddr, LIBNET_DONT_RESOLVE));
        (void)fprintf(stdout, "[%s] WARNING: Source address not assigned.\n", __progname);
    }

    if (dp->range > 1) {
        (void)fprintf(stdout, "[%s] WARNING: Assigning addresses sequentially from %s.\n", __progname,
                      dp->saddr);
        (void)fprintf(stdout, "[%s] WARNING: This may cause problems on your network if addresses conflict with other hosts!\n", __progname);
    }

    LIBNET_ERR(libnet_seed_prand(dp->l));
    dp->secret = libnet_get_prand(LIBNET_PRu32);

    /* pcap */
    (void)fprintf(stdout, "[%s] Connection exhaustion started.\n", __progname);
    (void)fprintf(stdout, "[%s] Using device: %s\n", __progname, dev);
    (void)snprintf(filt, MAXFILT, PCAP_FILT, dp->daddr, dp->dport);
    (void)fprintf(stdout, "[%s] Using filter: %s\n", __progname, filt);

    PCAP_ERRBUF(p = pcap_open_live(dev, SNAPLEN, PROMISC, TIMEOUT, errbuf));

    if (pcap_lookupnet(dev, &localnet, &netmask, errbuf) == -1)
        errx(EXIT_FAILURE, "%s\n", errbuf);

    PCAP_ERR(pcap_compile(p, &fcode, filt, 1 /* optimize == true */, netmask));
    PCAP_ERR(pcap_setfilter(p, &fcode));

    switch (pcap_datalink(p)) {
        case DLT_IEEE802_11:
            (void)fprintf(stderr, "[%s] Link layer is 802.11\n", __progname);
            break;
        case DLT_EN10MB:
            (void)fprintf(stderr, "[%s] Link layer is ethernet\n", __progname);
            break;
        default:
            (void)fprintf(stderr, "[%s] Link layer is unsupported\n", __progname);
            break;
    }

    if (create_arp_pool1(dp) < 0)
        warnx("Could not create ARP pool");

    (void)signal(SIGHUP, drench_cleanup);
    (void)signal(SIGQUIT, drench_cleanup);
    (void)signal(SIGINT, drench_cleanup);
    (void)signal(SIGTERM, drench_cleanup);

    if ( (pid = fork()) == -1)
        err(EXIT_FAILURE, "fork");

    /* begin by sending SYN packets */
    if (pid == 0)
        drench_writer(dp, count, group, usec);

    drench_reader(dp, p);

    (void)destroy_arp_pool1(dp);
    libnet_destroy(dp->l);
    free(dp->saddr);
    free(dp);
    exit (EXIT_FAILURE);
}


    void
drench_writer(pkt_t *dp, u_int32_t count, u_int32_t group, u_int32_t usec)
{
    u_int32_t range = 0;

    dp->flags = TH_SYN;

    while (range < count) {
        DRENCH_EXIT("writer", exit(EXIT_SUCCESS));

        drench_send_tcp(dp, range%dp->range, NULL);
        if ( (usec > 0) && (range%group == 0))
            usleep(usec);

        range++;
        if ( (dp->opts & O_REPEAT) && (range == count)) {
            usleep( (usec + 1) * 1000);
            range = 0;
        }
    }

    exit (EXIT_SUCCESS);
}

    void
drench_reader(pkt_t *dp, pcap_t *p)
{
    struct pcap_pkthdr hdr; 
    struct ip *ih = NULL;
    struct tcphdr *th = NULL;

    u_char *pkt = NULL;

    for ( ; ; ) {
        DRENCH_EXIT("reader", return);

        pkt = (u_char *)pcap_next(p, &hdr);
        if (pkt == NULL)
            continue;

        ih = (struct ip *)(pkt + sizeof(struct ether_header));
        th = (struct tcphdr *)(pkt + sizeof(struct ether_header) + sizeof(struct ip));

        if (th->th_flags & (TH_SYN|TH_ACK)) {
            dp->winsize = TCP_WINSIZE;
            dp->flags = TH_ACK;
            drench_send_tcp(dp, 0, pkt);

            /* Send a second ACK with window size set to 0 */
            if (dp->opts & O_ACK) {
                dp->winsize = 0;
                th->th_seq++;
                drench_send_tcp(dp, 0, pkt);
            }
        }
        else if ( (th->th_flags & TH_ACK) && !(th->th_flags & TH_FIN) &&
                (dp->opts & O_ACK)) {
            dp->winsize = 0;
            drench_send_tcp(dp, 0, pkt);
        }
        else {
            (void)fprintf(stdout, "(S->C)[");
            ISSET(TH_SYN, S);
            ISSET(TH_RST, R);
            ISSET(TH_FIN, F);
            ISSET(TH_ACK, A);
            ISSET(TH_URG, U);
            ISSET(TH_PUSH, P);

            (void)fprintf(stdout, "] SRC = %15s:%-6u ",
                          inet_ntoa(ih->ip_src), ntohs(th->th_sport));
            (void)fprintf(stdout, "DST = %15s:%-6u (ignoring)\n",
                          inet_ntoa(ih->ip_dst), ntohs(th->th_dport));
        }
    }
}

    void
drench_cleanup(int sig)
{
    drench_exit = 1;
}

    void
usage(void)
{
    (void)fprintf(stdout, "[%s v%s: Connection flood utility]\n",
                  __progname, DRENCH_BUILD);
    (void)fprintf(stdout, "Usage: %s [-h|-i <interface>|-d <address>|-p <port>|-P <payload>|-r <number>|-s <address>|-c <number>|-C|-S <microseconds>|-x <group>]\n", __progname);
    (void)fprintf(stdout, "-h\t\tusage\n");
    (void)fprintf(stdout, "\n");
    (void)fprintf(stdout, "-d <address>\tdestination address\n");
    (void)fprintf(stdout, "-p <port>\tport to connection flood\n");
    (void)fprintf(stdout, "\n");
    (void)fprintf(stdout, "-c <number>\tpacket count\n");
    (void)fprintf(stdout, "-i <interface>\tinterface\n");
    (void)fprintf(stdout, "-r <number>\tnumber of ARP'ed fake IP addresses\n");
    (void)fprintf(stdout, "-s <address>\tsource address\n");
    (void)fprintf(stdout, "\n");
    (void)fprintf(stdout, "-A \t\tRespond to received ACK's\n");
    (void)fprintf(stdout, "-C \t\tDisable check of ISN cookie\n");
    (void)fprintf(stdout, "-P <payload>\tpayload of packet\n");
    (void)fprintf(stdout, "-R \t\tRepeat packet burst\n");
    (void)fprintf(stdout, "-S <microseconds>\tmicroseconds to sleep between sending packets\n");
    (void)fprintf(stdout, "-x <group>\tnumber of packets to send in a group (defaults to value of -r)\n");
    (void)fprintf(stdout, "\n[Bug reports to michael.santos@gmail.com]\n");

    exit (EXIT_FAILURE);
}
