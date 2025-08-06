import matplotlib.pyplot as plt
import numpy as np

# X-axis: Number of inner products
inner_product_counts = [4, 8, 16, 32, 64, 128, 256]

# Y-axis: Execution times per iteration for each thread count
times_4_threads =    [0.124099, 0.246802, 0.492425, 0.981191, 1.98259, 3.96763, 7.93819]
times_8_threads =    [0.123605, 0.124174, 0.247066, 0.492572, 0.982333, 1.98258, 3.96942]
times_16_threads =   [0.12382,  0.124091, 0.196201, 0.380614, 0.759579, 1.50485,  2.93509]
times_32_threads =   [0.124117, 0.124269, 0.193672, 0.354574, 0.68366,  1.3575,   2.7069]

# Plotting
plt.figure(figsize=(10, 6))

plt.plot(inner_product_counts, times_4_threads, color='red', linewidth=1.5, label='4 threads')
plt.plot(inner_product_counts, times_8_threads, color='green', linewidth=1.5, label='8 threads')
plt.plot(inner_product_counts, times_16_threads, color='blue', linewidth=1.5, label='16 threads')
plt.plot(inner_product_counts, times_32_threads, color='orange', linewidth=1.5, label='32 threads')

# Apply log scale to Y-axis
#plt.yscale("log")

# Labels and Title
plt.xlabel('Number of Inner Products (parallel)', fontsize=12)
plt.ylabel('Execution Time per Iteration (seconds)', fontsize=12)
plt.title('Execution Time vs Inner Product Count', fontsize=14)

# Grid like in the example
plt.grid(True, which='both', linestyle=':', color='black', alpha=0.5)

# Ticks
plt.xticks(inner_product_counts)
#plt.minorticks_on()

# Legend
plt.legend()

# Layout and show
plt.tight_layout()
plt.show()
