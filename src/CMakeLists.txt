include_directories("${Boost_INCLUDE_DIRS}")
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -isystem ${Boost_INCLUDE_DIRS}")

add_executable(regexbench
  regexbench.cpp)
target_link_libraries(regexbench
  ${Boost_LIBRARIES})
