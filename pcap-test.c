#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define BUFSIZE 1024

typedef struct EthernetHeader {
    unsigned char des_mac[6];
    unsigned char src_mac[6];
    unsigned short type;
} EthernetH;

typedef struct IPHeader {
    unsigned char version_ihl;
    unsigned char tos;
    unsigned short len;
    unsigned short id;
    unsigned short flags_frag_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short headerCheck;
    struct in_addr srcadd;
    struct in_addr dstadd;
} IPH;

typedef struct TCPHeader {
    unsigned short srcport;
    unsigned short dstport;
    unsigned int sequence_number;
    unsigned int acknowledgement_number;
    unsigned char offset_reserved_flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} TCPH;

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void PrintEthernetHeader(const u_char* packet) {
    EthernetH* eh = (EthernetH*)packet;
    printf("\n======== Ethernet Header ========\n");
    printf("Dst Mac %02x:%02x:%02x:%02x:%02x:%02x \n", 
        eh->des_mac[0], eh->des_mac[1], eh->des_mac[2], 
        eh->des_mac[3], eh->des_mac[4], eh->des_mac[5]);
    printf("Src Mac %02x:%02x:%02x:%02x:%02x:%02x \n", 
        eh->src_mac[0], eh->src_mac[1], eh->src_mac[2], 
        eh->src_mac[3], eh->src_mac[4], eh->src_mac[5]);
}

void PrintIPHeader(const u_char* packet) {
    IPH* ih = (IPH*)packet;
    printf("======== IP Header ========\n");
    printf("Src IP  : %s\n", inet_ntoa(ih->srcadd));
    printf("Dst IP  : %s\n", inet_ntoa(ih->dstadd));
}

void PrintTCPHeader(const u_char* packet) {
    TCPH* th = (TCPH*)packet;
    printf("======== TCP Header ========\n");
    printf("Src Port : %d\n", ntohs(th->srcport));
    printf("Dst Port : %d\n", ntohs(th->dstport));
}

void PrintPayload(const u_char* payload, int length) {
    printf("======== Payload (First 20 bytes) ========\n");
    for (int i = 0; i < 20 && i < length; ++i) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZE, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("%u bytes captured\n", header->caplen);

        // Ethernet Header
        PrintEthernetHeader(packet);
        packet += sizeof(EthernetH);

        // IP Header
        PrintIPHeader(packet);
        IPH* iph = (IPH*)packet;
        int ip_header_length = (iph->version_ihl & 0x0F) * 4;
        packet += ip_header_length;

        // TCP Header
        if (iph->protocol == IPPROTO_TCP) {
            PrintTCPHeader(packet);
            TCPH* tcph = (TCPH*)packet;
            int tcp_header_length = (tcph->offset_reserved_flags >> 4) * 4;
            packet += tcp_header_length;

            int payload_length = header->caplen - (sizeof(EthernetH) + ip_header_length + tcp_header_length);
            PrintPayload(packet, payload_length);
        }
    }

    pcap_close(pcap);
    return 0;
}
