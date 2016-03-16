include_directories("${Boost_INCLUDE_DIRS}")
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -isystem ${Boost_INCLUDE_DIRS}")
include_directories("${PCAP_INCLUDE_DIR}")
if(NOT (PCAP_INCLUDE_DIR STREQUAL Boost_INCLUDE_DIRS))
  set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -isystem ${PCAP_INCLUDE_DIR}")
endif()

add_executable(regexbench
  match.cpp PcapSource.cpp regexbench.cpp Rule.cpp)
target_link_libraries(regexbench
  ${Boost_LIBRARIES} ${PCAP_LIB})
