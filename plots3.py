import matplotlib.pyplot as plt
import numpy as np

# Depths
depths = np.array([3, 4, 6, 8])

# RotationKeyGen latencies in microseconds
lattigo_latency = [260220, 317029, 1303860, 1750436]
seal_latency = [102828, 157745, 705779, 1203090]
openfhe_latency = [91161, 135099, 329459, 400394]

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
plt.yticks([10**5, 10**6, 10**7])  # For large rotation keygen times

# Grid + legend
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.legend(loc='upper left')

# Save to PDF
plt.tight_layout()
plt.savefig("plot3.pdf", bbox_inches='tight')
plt.close()
