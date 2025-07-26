project(OpenFHE_lib LANGUAGES CXX)

#multithread_openfhe_inner
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

#tests_openFHE
add_executable(tests_openFHE tests_openFHE.cpp mult_openFHE.cpp)

target_link_libraries(tests_openFHE
    OPENFHEpke
    OPENFHEcore
)

target_include_directories(tests_openFHE PRIVATE 
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe/pke
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe/core
    ${CMAKE_SOURCE_DIR}/install-openfhe/include/openfhe/binfhe
    ${CMAKE_CURRENT_LIST_DIR}

)

set_target_properties(tests_openFHE PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)

