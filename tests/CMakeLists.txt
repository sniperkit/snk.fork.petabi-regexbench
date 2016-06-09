find_path(ATF_INCLUDE_DIR atf-c++.hpp)

include_directories("${ATF_INCLUDE_DIR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Kyuafile.in
  ${CMAKE_CURRENT_BINARY_DIR}/Kyuafile)

add_definitions(-DDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

if(RE2_INCLUDE_DIR)
  include_directories("${RE2_INCLUDE_DIR}")
  if(NOT (RE2_INCLUDE_DIR STREQUAL Boost_INCLUDE_DIRS))
    set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -isystem ${RE2_INCLUDE_DIR}")
  endif()
endif()
if(REMATCH_INCLUDE_DIR)
  include_directories("${REMATCH_INCLUDE_DIR}")
  if(NOT (REMATCH_INCLUDE_DIR STREQUAL Boost_INCLUDE_DIRS))
    set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -isystem ${REMATCH_INCLUDE_DIR}")
  endif()
endif()

add_executable(t_metadata t_metadata.cpp
  ../src/match.cpp ../src/PcapSource.cpp ../src/Rule.cpp ../src/session.cpp)
target_link_libraries(t_metadata ${ATF_LIB} ${PCAP_LIB})

add_executable(t_session t_session.cpp ../src/REmatchEngine.cpp ../src/Engine.cpp
  ../src/match.cpp ../src/PcapSource.cpp ../src/Rule.cpp ../src/session.cpp)
target_link_libraries(t_session ${ATF_LIB} ${PCAP_LIB} ${PCRE2_LIB})

if(REMATCHCOMP_LIB)
  target_link_libraries(t_session ${REMATCHCOMP_LIB} ${REMATCHEXEC_LIB})
endif()

