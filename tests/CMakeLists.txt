find_path(ATF_INCLUDE_DIR atf-c++.hpp)

include_directories("${ATF_INCLUDE_DIR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Kyuafile.in
  ${CMAKE_CURRENT_BINARY_DIR}/Kyuafile)

add_definitions(-DDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(t_metadata t_metadata.cpp
  ../src/match.cpp ../src/PcapSource.cpp ../src/Rule.cpp ../src/Session.cpp)
target_link_libraries(t_metadata ${ATF_LIB} ${PCAP_LIB})

add_executable(t_session t_session.cpp ../src/Engine.cpp
  ../src/match.cpp ../src/PcapSource.cpp ../src/Rule.cpp ../src/Session.cpp)
target_link_libraries(t_session engines ${ATF_LIB} ${PCAP_LIB})

add_executable(t_re2 t_re2.cpp ../src/Engine.cpp
  ../src/match.cpp ../src/PcapSource.cpp ../src/Rule.cpp ../src/Session.cpp)
target_link_libraries(t_re2 engines ${ATF_LIB} ${PCAP_LIB})

add_executable(t_option t_option.cpp ${ENGINE_SRCS}
  ../src/match.cpp
  ../src/PcapSource.cpp ../src/Rule.cpp ../src/Session.cpp)
target_link_libraries(t_option
  engines ${ATF_LIB} ${PCAP_LIB} ${Boost_LIBRARIES})
if(PCRE2_LIB)
  target_link_libraries(t_option ${PCRE2_LIB})
endif()
