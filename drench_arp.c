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

#define ARP         "/usr/sbin/arp"
#define BUFSZ       1024
#define MAC_ADDR    "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_COMPONENTS  6

#if 0
    int
create_arp_pool(libnet_t *l, u_int8_t iprange)
{
    u_int32_t ipaddr = 0;
    char *ipsrc = NULL;

    arp_t *arp = NULL;
    struct arp_entry *entry = NULL;
    int i = 0;

    ISNULL(entry = (struct arp_entry *)calloc(1, sizeof(struct arp_entry)));
    ISNULL(ipaddr = libnet_get_ipaddr4(l));

    (void)fprintf(stdout, "[Your IP address is %s]\n", libnet_addr2name4(ipaddr, LIBNET_DONT_RESOLVE));

    if ( (arp = arp_open()) == NULL)
        errx(EXIT_FAILURE, "Could not get ARP descriptor.");

    for ( i = 1; i < iprange; i++ ) {
        /* Generate a fake MAC address */
        if (addr_pton(MAC_ADDR, &entry->arp_ha) < 0)
            err(EXIT_FAILURE, "addr_pton");

        /* Generate a fake IP address */
        ipsrc = libnet_addr2name4(ipaddr + i, LIBNET_DONT_RESOLVE);
        if (addr_pton(ipsrc, &entry->arp_pa) < 0)
            err(EXIT_FAILURE, "addr_pton");

        if (arp_add(arp, entry) < 0)
            err(EXIT_FAILURE, "arp_add");

        (void)fprintf(stdout, "Added entry for %s\n", ipsrc);
    }

    (void)arp_close(arp);
    return (0);
}
#endif /* 0 */


    int
create_arp_pool1(pkt_t *dp)
{
    u_int32_t ipaddr = 0;
    char *ipsrc = NULL;
    char *arp = NULL;
    char *macaddr = NULL;
    u_int8_t mac[MAC_COMPONENTS];
    int i = 0;
    int j = 0;
    int ret = 0;

    libnet_t *l = dp->l;
    u_int8_t iprange = dp->range;

    ISNULL(arp = (char *)calloc(BUFSZ, 1));
    ISNULL(macaddr = (char *)calloc(MAC_COMPONENTS * 3, 1));

    LIBNET_ERR(ipaddr = libnet_name2addr4(l, dp->saddr, LIBNET_DONT_RESOLVE));

    for ( i = 0; i < iprange; i++ ) {
        /* Prepare our MAC address */
        for (j = 0; j < MAC_COMPONENTS; j++)
            mac[j] = (u_int8_t)libnet_get_prand(LIBNET_PR8);

        (void)sprintf(macaddr, MAC_ADDR, mac[0], mac[1], mac[2],
                      mac[3], mac[4], mac[5]);

        /* Generate a fake IP address */
        ipsrc = libnet_addr2name4(htonl(ntohl(ipaddr) + i), LIBNET_DONT_RESOLVE);

        ret = snprintf(arp, BUFSZ, "%s -s %s %s pub >/dev/null 2>&1",
                ARP, ipsrc, macaddr);

        if ( (ret < 0) || (ret >= BUFSZ)) {
            (void)fprintf(stdout, "[%s] Could not create arp command\n", __progname);
            exit(EXIT_FAILURE);
        }

        ret = system(arp);
        switch (ret) {
            case 0:
                (void)fprintf(stdout, "[%s] added ARP entry for MAC %s, IP %s\n",
                              __progname, macaddr, ipsrc);
                break;
            case 256:
                (void)fprintf(stdout, "[%s] MAC address already in ARP table: %s, %s\n", __progname, macaddr,
                        ipsrc);
                break;
            case 127:
                (void)fprintf(stdout, "[%s] failed to spawn shell\n", __progname);
                exit(ret);
            case -1:
                (void)fprintf(stdout, "[%s] could not fork\n", __progname);
                exit(ret);
            default:
                (void)fprintf(stdout, "[%s] \"%s\" failed with value %d\n", __progname, arp, ret);
                break;
        }
    }

    free(arp);
    return (0);
}

    int
destroy_arp_pool1(pkt_t *dp)
{
    u_long ipaddr = 0;
    char *ipsrc = NULL;
    char *arp = NULL;
    int i = 0;
    int ret = 0;

    libnet_t *l = dp->l;
    u_int8_t iprange = dp->range;

    ISNULL(arp = (char *)calloc(BUFSZ, 1));
    LIBNET_ERR(ipaddr = libnet_name2addr4(l, dp->saddr, LIBNET_DONT_RESOLVE));

    for ( i = 0; i < iprange; i++ ) {
        ipsrc = libnet_addr2name4(htonl(ntohl(ipaddr) + i), LIBNET_DONT_RESOLVE);

        ret = snprintf(arp, BUFSZ, "%s -d %s >/dev/null 2>&1", ARP, ipsrc);

        if ( (ret < 0) || (ret >= BUFSZ)) {
            (void)fprintf(stdout, "[%s] Could not create arp command\n", __progname);
            exit (EXIT_FAILURE);
        }

        ret = system(arp);
        switch (ret) {
            case 0:
                (void)fprintf(stdout, "[%s] Deleted entry for %s\n", __progname,
                              ipsrc);
                break;
            case 256:
                (void)fprintf(stdout, "[%s] ARP entry does not exist or cannot be removed: %s\n", __progname,
                              ipsrc);
                break;
            case 127:
                (void)fprintf(stdout, "[%s] failed to spawn shell", __progname);
                exit(ret);
            case -1:
                (void)fprintf(stdout, "[%s] could not fork", __progname);
                exit(ret);
            default:
                (void)fprintf(stdout, "[%s] \"%s\" failed with value %d\n", __progname,
                        arp, ret);
                break;
        }
    }

    free(arp);
    return (0);
}
