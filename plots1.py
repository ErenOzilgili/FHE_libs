import matplotlib.pyplot as plt
import numpy as np

# Depth values
depths = np.array([3, 4, 6, 8])

# KeyGen latencies in microseconds
lattigo_latency = [8623, 9321, 19390, 21163]
seal_latency = [2979, 3549, 9699, 12137]
openfhe_latency = [14506, 15601, 42971, 55000]

# Plot
plt.figure(figsize=(6, 4))
plt.plot(depths, seal_latency, label="SEAL", color='black')
plt.plot(depths, openfhe_latency, label="OpenFHE", color='gray')
plt.plot(depths, lattigo_latency, label="Lattigo", color='lightgray')

# Axes scales and labels
plt.yscale('log')
plt.ylabel("Latency (μs)")
plt.xlabel("Configuration Depths")

plt.xticks([3, 4, 6, 8])
plt.yticks([10**2, 10**3, 10**4, 10**5])  # suitable for 2,000–55,000 μs range

# Grid and legend
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.legend(loc='upper left')

# Save
plt.tight_layout()
plt.savefig("plot1.pdf", bbox_inches='tight')
plt.close()
