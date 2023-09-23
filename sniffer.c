#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct ipheader { 
    unsigned char iph_ihl: 4, iph_ver: 4;
    unsigned char iph_tos;

    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag: 3, iph_offset: 13;

    unsigned char iph_ttl;
    unsigned char iph_protocol;

    unsigned short int iph_chksum;

    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    
    u_int tcp_seq;
    u_int tcp_ack;

    u_char tcp_offx2;

    #define TH_OFF(th)  (((th)->tcp_offx2 & 0xf0) >> 4)

    u_char tcp_flags;

    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS ( TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG | TH_ECE | TH_CWR )

    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

        // MAC Address for source
        printf("    FROM MAC : ");

        for (int i = 0; i < 5; i++) {
            printf("%02x:", eth->ether_shost[i]);

            if (i == 4) {
                printf("%02x\n", eth->ether_shost[5]);
            }
        }

        // MAC Address for dest
        printf("    TO MAC : ");

        for (int j = 0; j < 5; j++) {
            printf("%02x:", eth->ether_dhost[j]);

            if (j == 4) {
                printf("%02x\n", eth->ether_dhost[5]);
            }
        }

        // Got ip header print source, dest ip
        printf("    FROM IP : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("    TO IP : %s\n", inet_ntoa(ip->iph_destip));
        
        // Got source, dest port in TCP header
        printf("    FROM PORT : %d\n", ntohs(tcp->tcp_sport));
        printf("    TO PORT : %d\n", ntohs(tcp->tcp_dport));

        // calc ip, tcp header len
        int ip_header_len = ip->iph_ihl << 2;
        int tcp_header_len = tcp->tcp_offx2 << 2;

        // get Message array
        unsigned char *message = (unsigned char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);

        // get message full len
        int message_len = ntohs(ip->iph_len) - (ip_header_len + tcp_header_len);

        printf("    FROM Data : ");

        for (int k = 0; k < message_len; k++) {
            printf("%02x ", message[k]);
        }

        printf("\n");

        // switch protocol but, only case TCP
        switch (ip->iph_protocol) {
            case IPPROTO_TCP:
                printf("    PROTOCOL : TCP\n");
                return;
            case IPPROTO_UDP:
                printf("    PROTOCOL : UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("    PROTOCOL : ICMP\n");
                return;
            default:
                printf("     PROTOCOL : OTHERS\n");
                return;
        }
    }
}

int main() {
    pcap_t *handle;

    char errbuf[PCAP_ERRBUF_SIZE];
    
    struct bpf_program fp;

    char filter_exp[] = "tcp";

    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}