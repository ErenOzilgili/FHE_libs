import matplotlib.pyplot as plt
import numpy as np

# Depths
depths = np.array([3, 4, 6, 8])

# Addition latencies in microseconds
lattigo_latency = [246, 212, 586, 800]
seal_latency = [297, 393, 1171, 1565]
openfhe_latency = [201, 237, 645, 824]

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
plt.yticks([10**2, 10**3])  # For range ~200–1500 μs

# Grid + legend
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.legend(loc='upper left')

# Save to PDF
plt.tight_layout()
plt.savefig("plot5.pdf", bbox_inches='tight')
plt.close()
