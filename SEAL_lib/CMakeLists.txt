project(SEAL_lib LANGUAGES CXX)

# tests_seal
add_executable(tests_seal tests_seal.cpp mult_seal.cpp inner_seal.cpp)
target_link_libraries(tests_seal SEAL::seal)

target_include_directories(tests_seal PRIVATE ${CMAKE_CURRENT_LIST_DIR})

set_target_properties(tests_seal PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)
