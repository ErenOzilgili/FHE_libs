project(SEAL_lib LANGUAGES CXX)

add_executable(multithread_seal_inner multithread_seal_inner.cpp)
target_link_libraries(multithread_seal_inner SEAL::seal)

target_include_directories(multithread_seal_inner PRIVATE ${CMAKE_CURRENT_LIST_DIR})

set_target_properties(multithread_seal_inner PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)

