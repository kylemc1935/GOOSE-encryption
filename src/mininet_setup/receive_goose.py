#!/usr/bin/python
from scapy.all import sniff, Ether, Raw, wrpcap, sendp
import argparse
import signal
import sys, time, matplotlib.pyplot as plt, csv
import struct

key = b'\x00' * 32
nonce = b'\x00' * 16
no_packets = 0
no_received = 0
captured_packets = []
pcap_filename = None

# throughput measurement
throughput_start = time.time()
bytes_received = 0
throughput_interval = 0.01
throughput_measurements = []
throughput_timestamps = []
overall_start = None
timeout = None  #  timeout variable
measure_thp = False

def process_packet(pkt):
    global no_packets, no_received, captured_packets
    global throughput_start, bytes_received, throughput_interval
    global throughput_measurements, throughput_timestamps, overall_start, measure_thp

    no_received += 1
    pkt_len = len(pkt)
    print(f"packet {no_received} received of {pkt_len} bytes")

    if measure_thp:
        bytes_received += pkt_len
        current_time = time.time()
        if current_time - throughput_start >= throughput_interval:
            throughput_bps = (bytes_received * 8) / (current_time - throughput_start)
            print(f"Throughput: {throughput_bps:.2f}bps ----------------", flush=True)
            if overall_start is not None:
                relative_time = current_time - overall_start
                throughput_measurements.append(throughput_bps)
                throughput_timestamps.append(relative_time)
            throughput_start = current_time
            bytes_received = 0

    if pkt.haslayer(Raw) and pkt.haslayer(Ether):
        if pkt[Ether].type == 0x88b8:
            print("----------GOOSE packet received---------")
            if pcap_filename:
                captured_packets.append(pkt)
                print("Packet stored")
                return
            if b'OperationalValues' in pkt[Raw].load:
                print("decrypted packet no:", no_received, "okay!")
                no_packets += 1
            else:
                print("***  error decrypting  ***")

def write_packets_on_exit(signum, frame):
    if pcap_filename:
        try:
            wrpcap(pcap_filename, captured_packets)
            print(f"packets written to {pcap_filename}")
        except Exception as e:
            print("error writing to file", e)
    sys.exit(0)

def plot_throughput(timestamps, measurements):
    plt.figure()
    plt.plot(timestamps, measurements, marker='o')
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (bps)")
    plt.title("Measured Throughput Over Time")
    plt.grid(True)
    plt.show()

def write_throughput_to_file(filename, timestamps, measurements):
    try:
        with open(filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Time (s)", "Throughput (bps)"])
            for t, m in zip(timestamps, measurements):
                writer.writerow([t, m])
        print(f"Throughput data written to {filename}")
    except Exception as e:
        print("Error writing throughput file:", e)

def start_listen():
    global pcap_filename, overall_start, measure_thp, timeout
    parser = argparse.ArgumentParser(
        description="Receive GOOSE packets, optionally measure throughput, and optionally save them to a pcap file."
    )
    parser.add_argument("--alg", help="Encryption algorithm (e.g., chacha)")
    parser.add_argument("--mode", help="Encryption mode (e.g., full)")
    parser.add_argument("--measure_throughput", action="store_true", help="Enable throughput measurement")
    parser.add_argument("--timeout", help="Sniffing timeout in seconds", default=None)
    args = parser.parse_args()

    measure_thp = args.measure_throughput
    if args.timeout is not None:
        timeout = float(args.timeout)
    else:
        timeout = None

    overall_start = time.time()

    if args.alg and args.mode:
        pcap_filename = f"../data/algorithm_mode/{args.alg}_{args.mode}.pcap"
        print(f"Packets will be written to: {pcap_filename}")
    else:
        pcap_filename = None
        print("No packets will be written to files.")

    if measure_thp:
        overall_start = time.time()

    interface = "H2-eth0"
    print("Listening on", interface)

    signal.signal(signal.SIGTERM, write_packets_on_exit)
    signal.signal(signal.SIGINT, write_packets_on_exit)

    try:
        if timeout is None:
            sniff(iface=interface, prn=process_packet)
        else:
            sniff(iface=interface, prn=process_packet, timeout=timeout)
        if measure_thp and throughput_measurements:
            if args.alg and args.mode:
                throughput_filename = f"../data/throughput/{args.alg}_{args.mode}_throughput.csv"
                write_throughput_to_file(throughput_filename, throughput_timestamps, throughput_measurements)
    except Exception as e:
        print("Error during sniffing:", e)

    if pcap_filename:
        try:
            wrpcap(pcap_filename, captured_packets)
            print(f"Packets written to {pcap_filename}")
        except Exception as e:
            print("Error writing to file", e)

def main():
    start_listen()

if __name__ == "__main__":
    main()
