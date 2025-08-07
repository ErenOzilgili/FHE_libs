import matplotlib.pyplot as plt
import numpy as np

# Depths
depths = np.array([3, 4, 6, 8])

# Rotation latencies in microseconds
lattigo_latency = [1524, 1655, 3806, 8832]
seal_latency = [3525, 5202, 26305, 31991]
openfhe_latency = [41992, 67216, 197205, 252468]

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
plt.yticks([10**3, 10**4, 10**5])  # Suitable for 1,500–250,000 μs

# Grid + legend
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.legend(loc='upper left')

# Save to PDF
plt.tight_layout()
plt.savefig("plot6.pdf", bbox_inches='tight')
plt.close()
