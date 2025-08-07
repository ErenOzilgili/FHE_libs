import matplotlib.pyplot as plt
import numpy as np

# Depth values
depths = np.array([3, 4, 6, 8])

# RelinKeyGen latencies in microseconds
lattigo_latency = [23685, 32307, 104696, 137171]
seal_latency = [8397, 12923, 54434, 91055]
openfhe_latency = [5832, 8994, 24891, 31600]

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
plt.yticks([10**3, 10**4, 10**5])  # good for 5,000–140,000 range

# Grid + legend
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.legend(loc='upper left')

# Save
plt.tight_layout()
plt.savefig("plot2.pdf", bbox_inches='tight')
plt.close()
