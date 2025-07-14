#SEPERATE BUILT VERSION
#--------------------
cmake_minimum_required(VERSION 3.14)
project(FHE_libs LANGUAGES CXX)

# Add the install paths for SEAL and OpenFHE:
#list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_LIST_DIR}/../install-seal")
#list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_LIST_DIR}/../install-openfhe")
file(GLOB SEAL_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/install-seal/lib/cmake/SEAL-*")
list(APPEND CMAKE_PREFIX_PATH ${SEAL_CMAKE_DIR})
file(GLOB OpenFHE_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/install-openfhe/lib/OpenFHE")
list(APPEND CMAKE_PREFIX_PATH ${OpenFHE_CMAKE_DIR})


# Find them as packages:
find_package(SEAL REQUIRED)
find_package(OpenFHE REQUIRED)

# Add your custom modules:
add_subdirectory(SEAL_lib)
add_subdirectory(OpenFHE_lib)

