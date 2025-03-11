#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <pcap.h>

#include "../encryption_timings/encryption.h"
#include "../encryption_timings/encryption_config.h"
#include "../encryption_timings/latency.h"

#define ETHER_TYPE_CUSTOM 0x88b8
#define ETHERNET_HEADER_LEN 14

FILE *encryption_latency_file = NULL;  //record encryption time
FILE *decryption_latency_file = NULL;  //decryption time
unsigned long packet_count = 0;
int print_latency = 1;

encryption_config_t *chosen_config = NULL;

typedef struct {
    struct pcap_pkthdr header;
    u_char *data;
} packet_record_t;


// sends packets from pcap file
int send_pcap(const char *filename, const char *if_name, const unsigned char *dest_mac,
              encryption_config_t *chosen_config, int packet_limit) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_offline(filename, errbuf);
    if (!pcap_handle) {
         fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
         return -1;
    }

    // load all packets from the file.
    packet_record_t *packets = NULL;
    int num_packets = 0;
    const u_char *packet;
    struct pcap_pkthdr *header;
    int next_pkt;
    while ((next_pkt = pcap_next_ex(pcap_handle, &header, &packet)) >= 0) {
        if (next_pkt == 0) continue;
        packets = realloc(packets, (num_packets + 1) * sizeof(packet_record_t)); //adjust array size
        if (!packets) {
            perror("realloc");
            pcap_close(pcap_handle);
            return -1;
        }
        packets[num_packets].header = *header; // allocate data into struct
        packets[num_packets].data = malloc(header->len);
        if (!packets[num_packets].data) {
            perror("malloc");
            pcap_close(pcap_handle);
            return -1;
        }
        memcpy(packets[num_packets].data, packet, header->len);
        num_packets++;
    }
    pcap_close(pcap_handle); //close after reading in packets
    if (num_packets == 0) {
        fprintf(stderr, "No packets loaded from file.\n");
        return -1;
    }
    printf("Loaded %d packets from file.\n", num_packets);

    // create raw socket and get interface info
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE_CUSTOM));
    if (sockfd < 0) {
         perror("socket");
         return -1;
    }
    struct ifreq if_idx, if_mac;
    memset(&if_idx, 0, sizeof(if_idx));
    strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) { //get mac address of interace to send from
         perror("SIOCGIFINDEX");
         close(sockfd);
         return -1;
    }
    memset(&if_mac, 0, sizeof(if_mac));
    strncpy(if_mac.ifr_name, if_name, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) { //set up destination address
         perror("SIOCGIFHWADDR");
         close(sockfd);
         return -1;
    }
    struct sockaddr_ll socket_address; //set up destination address
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, dest_mac, ETH_ALEN);

    // send packets
    int seq = 0;
    for (int i = 0; i < packet_limit; i++) {
        int idx = i % num_packets;  // ensure there are packets to send after  reaching end of file
        packet_record_t *pr = &packets[idx];
        int new_packet_len = 0;
        uint8_t *new_packet = build_encrypted_packet(pr->data, pr->header.len, ETHERNET_HEADER_LEN,
                                                        &new_packet_len, chosen_config);

        if (!new_packet) {
            fprintf(stderr, "Failed to encrypt packet %d\n", seq);
            continue;
        }
        if (sendto(sockfd, new_packet, new_packet_len, 0,
                   (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            perror("sendto");
            free(new_packet);
            break;
        }
        printf("Sent encrypted packet seq %d, original length %d, new length %d\n",
               seq, pr->header.len, new_packet_len);
        seq++;
        free(new_packet);
    }

    // free all loaded packets.
    for (int i = 0; i < num_packets; i++) {
        free(packets[i].data);
    }
    free(packets);
    close(sockfd);
    return 0;
}

// decrypts incoming packets
void packet_handler_decrypt(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    long start_time = get_time_ns();
    packet_count++;

    //printf("Received packet of length %d bytes\n", header->len);

    // extract the timestamp header.
    struct timestamp_header ts_hdr;
    int new_len = 0;

    uint8_t *decrypted_packet = build_decrypted_packet(packet, header->len, ETHERNET_HEADER_LEN,
                                                        &new_len, chosen_config, &ts_hdr);
    if (!decrypted_packet)return;

    // calc latency based on header
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    long latency_ns = (now.tv_sec - ts_hdr.ts.tv_sec) * 1000000000L +
                      (now.tv_nsec - ts_hdr.ts.tv_nsec);
    double latency_ms = latency_ns / 1e6;
    long elapsed = get_time_ns() - start_time;

    //printf("Decryption elapsed time: %ld ns, Latency: %.3f ms\n", elapsed, latency_ms);

    if (packet_count > 10 && decryption_latency_file != NULL && print_latency &&
        latency_ms > 0 && latency_ms < 1000000) {
        fprintf(decryption_latency_file, "%s, %s, %ld, %.3f\n",
                chosen_config->name, mode_to_string(chosen_config->mode), elapsed, latency_ms);
        fflush(decryption_latency_file);
    }

    // send on packet as needed ...
    free(decrypted_packet);
}

// sets up a pcap handle on the specified interface and starts the capture loop
int receive_pcap(const char *if_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(if_name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return -1;
    }

    if (pcap_set_buffer_size(handle, 2*1024*1024) != 0) {
        fprintf(stderr, "Error setting buffer size: %s\n", pcap_geterr(handle));
    }
    if (pcap_set_immediate_mode(handle, 1) != 0) {
        fprintf(stderr, "Error setting immediate mode: %s\n", pcap_geterr(handle));
    }
    if (pcap_set_timeout(handle, 10) != 0) {
        fprintf(stderr, "Error setting capture timeout: %s\n", pcap_geterr(handle));
    }
    if (pcap_activate(handle) < 0) {
        fprintf(stderr, "Error activating capture handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    int ret = pcap_loop(handle, 0, packet_handler_decrypt, NULL);
    if (ret < 0) {
        fprintf(stderr, "Error in capture loop: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
       printf("Usage:\n");
       printf("  Sender:   %s send <pcap_file> <interface> <dest_mac> <algorithm> <mode> [packet_limit]\n", argv[0]);
       printf("  Receiver: %s recv <interface> <algorithm> <mode>\n", argv[0]);
       return 1;
    }

    encryption_config_t *conf = NULL;

    if (strcmp(argv[1], "send") == 0) { //sort send or recv params etc
       if (argc < 7 || argc > 8) {
          printf("Usage: %s send <pcap_file> <inteface> <dest_mac> <algorithm> <mode> [packet_limit]\n", argv[0]);
          return 1;
       }
       char *config_argv[3];
       config_argv[0] = argv[0];
       config_argv[1] = argv[5];
       config_argv[2] = argv[6];
       conf = get_chosen_config(3, config_argv);
    } else if (strcmp(argv[1], "recv") == 0) {
       if (argc != 5) {
          printf("Usage: %s recv <interface> <algorithm> <mode>\n", argv[0]);
          return 1;
       }
       char *config_argv[3];
       config_argv[0] = argv[0];
       config_argv[1] = argv[3];
       config_argv[2] = argv[4];
       conf = get_chosen_config(3, config_argv);
    } else {
       fprintf(stderr, "Unknown command: %s\n", argv[1]);
       return 1;
    }

    chosen_config = conf;

    //open latency files
    encryption_latency_file = fopen("../src/data/rp_data/encryption_latency_log.csv", "a");
    if (!encryption_latency_file) {
        perror("failed to open encryption latency file");
        return 1;
    }
    decryption_latency_file = fopen("../src/data/rp_data/decryption_latency_log.csv", "a");
    if (!decryption_latency_file) {
        perror("failed to open decryption latency file");
        return 1;
    }

    if (strcmp(argv[1], "send") == 0) {
       unsigned char dest_mac[6]; // get mac address for sending
       if (sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &dest_mac[0], &dest_mac[1], &dest_mac[2],
                  &dest_mac[3], &dest_mac[4], &dest_mac[5]) != 6) {
           fprintf(stderr, "Invalid MAC address format\n");
           return 1;
       }
       int packet_limit = 100; // sort packet limit
       if (argc == 8) {
           packet_limit = atoi(argv[7]);
       }

       return send_pcap(argv[2], argv[3], dest_mac, chosen_config, packet_limit);
    } else if (strcmp(argv[1], "recv") == 0) {
       return receive_pcap(argv[2]);
    }
    return 0;
}
