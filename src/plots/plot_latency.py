import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('../data/encryption_latency_log.csv', header=None, names=['algorithm', 'mode', 'latency'], sep=',')

print("Data Preview:")
print(df.head())

# Ggroup by algorithm and mode and compute average latency
avg_latencies = df.groupby(['algorithm', 'mode'])['latency'].mean().reset_index()

# Pivot the table so that the index is algorithm and columns are mode
pivot_table = avg_latencies.pivot(index='algorithm', columns='mode', values='latency')

print("Pivot Table:")
print(pivot_table)

plt.figure(figsize=(10, 7))
pivot_table.plot(kind='bar', figsize=(10, 7))
plt.xlabel('Algorithm')
plt.ylabel('Average Encryption Time (ns)')
plt.title('Average Encryption Time per Algorithm and Mode')
plt.xticks(rotation=45)
plt.legend(title='Mode')
plt.tight_layout()
plt.show()


# read file with four columns
df = pd.read_csv('../data/decryption_latency_log.csv', header=None,
                 names=['algorithm', 'mode', 'decrypt_latency', 'send_latency'], sep=',')

print("Data Preview:")
print(df.head())

# group by algorithm and mode and compute average decrpt latency
avg_decrypt = df.groupby(['algorithm', 'mode'])['decrypt_latency'].mean().reset_index()
pivot_decrypt = avg_decrypt.pivot(index='algorithm', columns='mode', values='decrypt_latency')

print("Decryption Latency Pivot Table:")
print(pivot_decrypt)

# group by algorithm and mode and compute average send latency
avg_send = df.groupby(['algorithm', 'mode'])['send_latency'].mean().reset_index()
pivot_send = avg_send.pivot(index='algorithm', columns='mode', values='send_latency')

print("Sending Latency Pivot Table:")
print(pivot_send)

plt.figure(figsize=(10, 7))
pivot_decrypt.plot(kind='bar', figsize=(10, 7))
plt.xlabel('Algorithm')
plt.ylabel('Average Decryption Latency (ns)')
plt.title('Average Decryption Latency per Algorithm and Mode')
plt.xticks(rotation=45)
plt.legend(title='Mode')
plt.tight_layout()
plt.show()

plt.figure(figsize=(10, 7))
pivot_send.plot(kind='bar', figsize=(10, 7))
plt.xlabel('Algorithm')
plt.ylabel('Average Sending Latency (ms)')
plt.title('Average Sending Latency per Algorithm and Mode')
plt.xticks(rotation=45)
plt.legend(title='Mode')
plt.tight_layout()
plt.show()