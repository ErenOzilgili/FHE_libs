# Inside OpenFHE_lib/CMakeLists.txt
"""
#ALL TOGETHER BUILT VERSION
#--------------------
project(OpenFHE_lib LANGUAGES CXX)

# Example executable using OpenFHE:
add_executable(multithread_openfhe_inner multithread_openfhe_inner.cpp)

# Link it to OpenFHE libraries:
# The specific OpenFHE target name may vary — typically something like openfhe-pke
target_link_libraries(multithread_openfhe_inner openfhe-pke) 

# Add this folder to include path for your helpers:
target_include_directories(multithread_openfhe_inner PRIVATE ${CMAKE_CURRENT_LIST_DIR})

# Put executables in a single bin folder
set_target_properties(multithread_openfhe_inner PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/executables
)

# Use C++17
set_target_properties(multithread_openfhe_inner PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)
"""

#SEPERATE BUILT VERSION
#--------------------
project(OpenFHE_lib LANGUAGES CXX)

add_executable(multithread_openfhe_inner multithread_openfhe_inner.cpp)
target_link_libraries(multithread_openfhe_inner OpenFHEpke::openfhe-pke)

target_include_directories(multithread_openfhe_inner PRIVATE ${CMAKE_CURRENT_LIST_DIR})

set_target_properties(multithread_openfhe_inner PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)

