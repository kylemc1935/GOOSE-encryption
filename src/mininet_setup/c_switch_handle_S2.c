#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "../encryption_timings/decryption.h"
#include "../encryption_timings/encryption_config.h"
#include "latency.h"

#define CAPTURE_IFACE "S2-eth1"
#define SEND_IFACE "S2-eth2"
#define ETHERNET_HEADER_LEN 14

int print_latency = 1;
int packet_count = 0;
pcap_t *send_handle = NULL;
encryption_config_t *chosen_config;
FILE *decryption_latency_file;
encryption_mode_t enc_mode;

//
void packet_handler_decrypt(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    long start_time, elapsed;
    start_time = get_time_ns();

    struct timestamp_header ts_hdr;
    int new_len = 0;

    uint8_t *decrypted_packet = build_decrypted_packet(packet, header->len, ETHERNET_HEADER_LEN,
                                                      &new_len, chosen_config, &ts_hdr);
    if (!decrypted_packet){
        printf("error decrypting packet");
        return;
    }

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    long latency_us = (now.tv_sec - ts_hdr.ts.tv_sec) * 1000000000L +
                      (now.tv_nsec - ts_hdr.ts.tv_nsec);
    double latency_ms = latency_us / 1e6;
    /*if (print_latency && latency_ms > -1) {
        printf("packet: %d, latency: %.3f ms\n", packet_count, latency_ms);
    }*/
    elapsed = get_time_ns() - start_time;
    //log_latency_ns("Packet decrypted", elapsed);

    if (packet_count > 10 && decryption_latency_file != NULL && print_latency && latency_ms > 0 && latency_ms < 1000000) {
        fprintf(decryption_latency_file, "%s, %s, %ld, %.3f\n", chosen_config->name, mode_to_string(chosen_config->mode), elapsed, latency_ms);
        fflush(decryption_latency_file);
    }

    if (pcap_sendpacket(send_handle, decrypted_packet, new_len) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(send_handle));
    }

    free(decrypted_packet);
}

int main(int argc, char *argv[]){
    // get config and latency file
    chosen_config = get_chosen_config(argc, argv);
    decryption_latency_file = fopen("../data/mn_data/decryption_latency_log.csv", "a");
    if(!decryption_latency_file) {
        perror("failed to open latency file");
        exit(EXIT_FAILURE);
    }


    char errbuf[PCAP_ERRBUF_SIZE]; // same as S1, create capture handle
    pcap_t *capture_handle = pcap_create(CAPTURE_IFACE, errbuf);
    if (capture_handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_set_buffer_size(capture_handle, 2 * 1024 * 1024) != 0) {
        fprintf(stderr, "Error setting capture buffer size: %s\n", pcap_geterr(capture_handle));
    }
    if (pcap_set_immediate_mode(capture_handle, 1) != 0) {
        fprintf(stderr, "Error setting capture immediate mode: %s\n", pcap_geterr(capture_handle));
    }
    if (pcap_set_timeout(capture_handle, 10) != 0) { // Set timeout to 10ms
        fprintf(stderr, "Error setting capture timeout: %s\n", pcap_geterr(capture_handle));
    }
    if (pcap_activate(capture_handle) < 0) {
        fprintf(stderr, "Error activating capture handle: %s\n", pcap_geterr(capture_handle));
        pcap_close(capture_handle);
        exit(EXIT_FAILURE);
    }
    if (pcap_setdirection(capture_handle, PCAP_D_IN) != 0) {
        fprintf(stderr, "Error setting capture direction: %s\n", pcap_geterr(capture_handle));
        pcap_close(capture_handle);
        exit(EXIT_FAILURE);
    }

    send_handle = pcap_create(SEND_IFACE, errbuf);  //setup send handle
    if (send_handle == NULL) {
        fprintf(stderr, "pcap_create for send_handle failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_set_buffer_size(send_handle, 2 * 1024 * 1024) != 0) {
        fprintf(stderr, "Error setting send buffer size: %s\n", pcap_geterr(send_handle));
    }
    if (pcap_set_immediate_mode(send_handle, 1) != 0) {
        fprintf(stderr, "Error setting send immediate mode: %s\n", pcap_geterr(send_handle));
    }
    if (pcap_set_timeout(send_handle, 10) != 0) { // Set timeout to 10ms
        fprintf(stderr, "Error setting send timeout: %s\n", pcap_geterr(send_handle));
    }
    if (pcap_activate(send_handle) < 0) {
        fprintf(stderr, "Error activating send_handle: %s\n", pcap_geterr(send_handle));
        pcap_close(send_handle);
        exit(EXIT_FAILURE);
    }

    //start capture loop
    if (pcap_loop(capture_handle, 0, packet_handler_decrypt, NULL) < 0) {
        fprintf(stderr, "Error in capture loop: %s\n", pcap_geterr(capture_handle));
    }

    pcap_close(capture_handle);
    pcap_close(send_handle);
    fclose(decryption_latency_file);

    return EXIT_SUCCESS;
}