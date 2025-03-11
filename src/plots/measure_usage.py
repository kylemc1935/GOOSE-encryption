#!/usr/bin/python
import psutil
import time
import argparse
import matplotlib.pyplot as plt


def monitor(pid, interval, duration):
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} not found.")
        return None, None, None

    times = []
    cpu_usage = []
    mem_usage = []

    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        # psutil.cpu_percent waits for the interval, so it measures usage over that time
        cpu = p.cpu_percent(interval=interval)
        mem = p.memory_info().rss / (1024 * 1024)  # convert bytes to MB
        timestamp = time.time() - start_time
        times.append(timestamp)
        cpu_usage.append(cpu)
        mem_usage.append(mem)
        print(f"[{timestamp:.2f}s] CPU: {cpu:.2f}% | Memory: {mem:.2f} MB")

    return times, cpu_usage, mem_usage


def main():
    parser = argparse.ArgumentParser(
        description="Monitor CPU and memory usage for a given process and plot the results."
    )
    parser.add_argument("--pid", type=int, required=True,
                        help="Process ID to monitor (e.g., the PID of your S1 switch process)")
    parser.add_argument("--interval", type=float, default=0.1,
                        help="Sampling interval in seconds (default: 1.0)")
    parser.add_argument("--duration", type=float, default=30.0,
                        help="Total duration to monitor in seconds (default: 60.0)")
    args = parser.parse_args()

    times, cpu_usage, mem_usage = monitor(args.pid, args.interval, args.duration)

    if times is None:
        return

    plt.figure(figsize=(12, 6))

    plt.subplot(2, 1, 1)
    plt.plot(times, cpu_usage, marker='o', linestyle='-')
    plt.xlabel("Time (s)")
    plt.ylabel("CPU Usage (%)")
    plt.title("CPU Usage Over Time")
    plt.grid(True)

    plt.subplot(2, 1, 2)
    plt.plot(times, mem_usage, marker='o', color='red', linestyle='-')
    plt.xlabel("Time (s)")
    plt.ylabel("Memory Usage (MB)")
    plt.title("Memory Usage Over Time")
    plt.grid(True)

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
