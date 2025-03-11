#!/usr/bin/python
import argparse
import csv
import matplotlib.pyplot as plt

def read_throughput_csv(filename):
    timestamps = []
    measurements = []
    with open(filename, "r") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader, None)
        for row in reader:
            # skip any row that is a header (in case it's repeated)
            if row and row[0] == "Time (s)":
                continue
            try:
                timestamps.append(float(row[0]))
                measurements.append(float(row[1]))
            except ValueError:
                continue
    return timestamps, measurements


def plot_throughput(timestamps, measurements, alg, mode):
    plt.figure()
    plt.plot(timestamps, measurements, marker='o')
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (bps)")
    plt.title(f"Throughput for {alg} in {mode} mode")
    plt.grid(True)
    plt.show()

def main():
    parser = argparse.ArgumentParser(
        description="Plot throughput measurements from a CSV file."
    )
    parser.add_argument("alg", help="Encryption algorithm")
    parser.add_argument("mode", help="Encryption mode")
    args = parser.parse_args()

    csv_filename = f"../data/throughput/{args.alg}_{args.mode}_throughput.csv"
    timestamps, measurements = read_throughput_csv(csv_filename)
    if not timestamps:
        print(f"No data found in {csv_filename}.")
        return
    plot_throughput(timestamps, measurements, args.alg, args.mode)

if __name__ == "__main__":
    main()
