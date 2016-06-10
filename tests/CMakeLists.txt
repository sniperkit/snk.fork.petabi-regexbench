find_path(ATF_INCLUDE_DIR atf-c++.hpp)

include_directories("${ATF_INCLUDE_DIR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Kyuafile.in
  ${CMAKE_CURRENT_BINARY_DIR}/Kyuafile)

set(ENGINE_SRCS ../src/Engine.cpp)
if(REMATCH_INCLUDE_DIR)
  include_directories("${REMATCH_INCLUDE_DIR}")
  if(NOT (REMATCH_INCLUDE_DIR STREQUAL Boost_INCLUDE_DIRS))
    set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -isystem ${REMATCH_INCLUDE_DIR}")
  endif()
  set(ENGINE_SRCS ${ENGINE_SRCS} ../src/REmatchEngine.cpp)
endif()

add_definitions(-DDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(t_metadata t_metadata.cpp
  ../src/match.cpp ../src/PcapSource.cpp ../src/Rule.cpp ../src/Session.cpp)

target_link_libraries(t_metadata ${ATF_LIB} ${PCAP_LIB})
add_executable(t_session t_session.cpp
  ../src/match.cpp ../src/PcapSource.cpp ../src/Rule.cpp ../src/Session.cpp
  ${ENGINE_SRCS})

target_link_libraries(t_session ${PCAP_LIB})
if(PCRE2_LIB)
  target_link_libraries(t_session ${PCRE2_LIB})
endif()
if(REMATCHCOMP_LIB)
  target_link_libraries(t_session ${REMATCHCOMP_LIB} ${REMATCHEXEC_LIB})
endif()
target_link_libraries(t_session ${ATF_LIB})
