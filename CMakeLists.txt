cmake_minimum_required(VERSION 2.8)

project(regexbench)
set(REGEXBENCH_VERSION_MAJOR 0)
set(REGEXBENCH_VERSION_MINOR 2)
set(REGEXBENCH_VERSION_PATCH 0)

set(CPACK_PACKAGE_VERSION
  "${REGEXBENCH_VERSION_MAJOR}.${REGEXBENCH_VERSION_MINOR}")
if(NOT ${REGEXBENCH_VERSION_PATCH} MATCHES "0")
  set(CPACK_PACKAGE_VERSION
    "${CPACK_PACKAGE_VERSION}.${REGEXBENCH_VERSION_PATCH}")
endif()
set(CPACK_PACKAGE_CONTACT "Min Sik Kim <msk@petabi.com>")
set(CPACK_PACKAGE_VENDOR "Petabi")
set(CPACK_GENERATOR "TBZ2")
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
  "${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_SOURCE_IGNORE_FILES
  "/build(-Debug|-Release)?/;/install/;/.git/;.DS_Store;~$;${CPACK_SOURCE_IGNORE_FILES}")

include(CPack)

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Weverything")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++98-compat")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++98-compat-pedantic")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "3.5")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
  endif()
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
endif()
if(NOT CMAKE_CXX_FLAGS MATCHES .*march.* AND
   NOT CMAKE_CXX_FLAGS_RELEASE MATCHES .*march.*)
  set(CMAKE_CXX_FLAGS_RELEASE
    "${CMAKE_CXX_FLAGS_RELEASE} -march=native -mtune=native")
endif()
if(NOT CMAKE_CXX_FLAGS_DEBUG MATCHES "-O")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
endif()
if(NOT CMAKE_CXX_FLAGS_RELEASE MATCHES "-O")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()

find_package(Boost REQUIRED COMPONENTS program_options)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIB pcap)

find_path(HYPERSCAN_INCLUDE_DIR hs/hs_compile.h)
find_library(HYPERSCAN_LIB hs)
find_path(REMATCH_INCLUDE_DIR rematch/rematch.h)
find_library(REMATCHCOMP_LIB rematchcomp)
find_library(REMATCHEXEC_LIB rematchexec)
find_library(PCRE2_LIB pcre2-8)

subdirs(src)
