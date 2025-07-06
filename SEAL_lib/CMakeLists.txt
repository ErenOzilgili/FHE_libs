# This CMakeLists.txt is *inside* SEAL_lib/

# Note: No need for cmake_minimum_required() here.
# Only top-level needs it.

# Use the parent project name:
project(SEAL_lib LANGUAGES CXX)

# Our sources are in this subdir:
add_executable(multithread_seal_inner multithread_seal_inner.cpp)

# Link to the SEAL library (which top-level added as subdir)
target_link_libraries(multithread_seal_inner seal)

# This subdir has its own headers:
target_include_directories(multithread_seal_inner PRIVATE ${CMAKE_CURRENT_LIST_DIR})

# C++17
set_target_properties(multithread_seal_inner PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)
