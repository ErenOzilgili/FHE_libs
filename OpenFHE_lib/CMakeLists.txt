project(OpenFHE_lib LANGUAGES CXX)

add_executable(multithread_openfhe_inner multithread_openfhe_inner.cpp)

target_link_libraries(multithread_openfhe_inner
    OPENFHEpke
    OPENFHEcore
)

target_include_directories(multithread_openfhe_inner PRIVATE 
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe/pke
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe/core
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe/binfhe
    ${CMAKE_CURRENT_LIST_DIR}

)

set_target_properties(multithread_openfhe_inner PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)

