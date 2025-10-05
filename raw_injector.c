#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <netpacket/packet.h>
#endif

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    int sockfd;
    struct ifreq if_idx;
    struct sockaddr_ll socket_address;
    char buffer[BUFFER_SIZE];
    ssize_t num_bytes;

    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface_name>\n", argv[0]);
        return 1;
    }
    const char *if_name = argv[1];
    
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket creation failed");
        return 1;
    }

    
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("ioctl SIOCGIFINDEX failed");
        close(sockfd);
        return 1;
    }

    
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN; 

    
    num_bytes = read(STDIN_FILENO, buffer, BUFFER_SIZE);
    if (num_bytes <= 0) {
        fprintf(stderr, "Error reading packet from stdin\n");
        close(sockfd);
        return 1;
    }

    
    if (sendto(sockfd, buffer, num_bytes, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto failed");
        close(sockfd);
        return 1;
    }
    
    
    printf("C: Successfully injected %zd byte packet on interface %s\n", num_bytes, if_name);

    close(sockfd);
    return 0;
}
