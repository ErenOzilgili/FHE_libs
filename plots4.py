import matplotlib.pyplot as plt
import numpy as np

# Depths
depths = np.array([3, 4, 6, 8])

# Encryption latencies in microseconds
lattigo_latency = [8793, 7091, 23608, 23993]
seal_latency = [5256, 6151, 17034, 21374]
openfhe_latency = [18988, 22396, 60019, 74758]

# Plot
plt.figure(figsize=(6, 4))
plt.plot(depths, seal_latency, label="SEAL", color='black')
plt.plot(depths, openfhe_latency, label="OpenFHE", color='gray')
plt.plot(depths, lattigo_latency, label="Lattigo", color='lightgray')

# Axes
plt.yscale('log')
plt.ylabel("Latency (μs)")
plt.xlabel("Configuration Depths")
plt.xticks([3, 4, 6, 8])
plt.yticks([10**3, 10**4, 10**5])  # Suitable for ~5,000–75,000 μs range

# Grid + legend
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.legend(loc='upper left')

# Save to PDF
plt.tight_layout()
plt.savefig("plot4.pdf", bbox_inches='tight')
plt.close()
