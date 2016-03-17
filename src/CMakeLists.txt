include_directories("${Boost_INCLUDE_DIRS}")
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -isystem ${Boost_INCLUDE_DIRS}")
include_directories("${PCAP_INCLUDE_DIR}")
if(NOT (PCAP_INCLUDE_DIR STREQUAL Boost_INCLUDE_DIRS))
  set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -isystem ${PCAP_INCLUDE_DIR}")
endif()

set(ENGINE_SRCS Engine.cpp)
if(HYPERSCAN_INCLUDE_DIR)
  include_directories("${HYPERSCAN_INCLUDE_DIR}")
  set(ENGINE_SRCS ${ENGINE_SRCS} HyperscanEngine.cpp)
endif()

add_executable(regexbench
  match.cpp PcapSource.cpp regexbench.cpp Rule.cpp
  ${ENGINE_SRCS})
target_link_libraries(regexbench
  ${Boost_LIBRARIES} ${PCAP_LIB})
if(HYPERSCAN_LIB)
  target_link_libraries(regexbench ${HYPERSCAN_LIB})
endif()
