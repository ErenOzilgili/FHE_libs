cmake_minimum_required(VERSION 3.14)
project(FHE_libs LANGUAGES CXX)

# Add SEAL submodule first so it's built and available
add_subdirectory(external/SEAL EXCLUDE_FROM_ALL)

# Add your SEAL-based tools (SEAL_lib/)
add_subdirectory(SEAL_lib)

# Add any other libraries the same way:
# add_subdirectory(other_lib)
