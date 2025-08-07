project(OpenFHE_lib LANGUAGES CXX)

#tests_openFHE
add_executable(tests_openFHE tests_openFHE.cpp mult_openFHE.cpp inner_openFHE.cpp)

#find_package(Threads REQUIRED)
target_link_libraries(tests_openFHE
    OPENFHEpke
    OPENFHEcore
    #Threads::Threads
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

