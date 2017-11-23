cmake_minimum_required(VERSION 3.1)
project(regexbench VERSION 0.2.2 LANGUAGES C CXX)

set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT "Min Sik Kim <msk@petabi.com>")
set(CPACK_PACKAGE_VENDOR "Petabi")
set(CPACK_GENERATOR "TBZ2")
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
  "${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_SOURCE_IGNORE_FILES
  "/build(-Debug|-Release)?/;/install/;/.git/;.DS_Store;~$;${CPACK_SOURCE_IGNORE_FILES}")

include(CPack)

option(WITH_SESSION "Test REmatch with session" ON)
if (WITH_SESSION)
  add_definitions(-DWITH_SESSION)
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Weverything")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++98-compat")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++98-compat-pedantic")
else()
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

include_directories(SYSTEM ${CMAKE_INSTALL_PREFIX}/include)

find_package(Boost REQUIRED COMPONENTS program_options regex system)
find_package(Threads REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIB pcap)

find_library(ATF_LIB atf-c++)

if(ATF_LIB)
  subdirs(tests)
endif()

find_path(HYPERSCAN_INCLUDE_DIR hs/hs_compile.h HINTS ${CMAKE_INSTALL_PREFIX}/include)
find_library(HYPERSCAN_LIB
  NAMES hs
  HINTS ${CMAKE_INSTALL_PREFIX}/lib)
if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIB)
  set(HAVE_HYPERSCAN 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "Hyperscan ")
  include_directories(SYSTEM ${HYPERSCAN_INCLUDE_DIR})
endif()
find_path(PCRE2_INCLUDE_DIR pcre2.h HINTS ${CMAKE_INSTALL_PREFIX}/include)
find_library(PCRE2_LIB
  NAMES pcre2-8
  HINTS ${CMAKE_INSTALL_PREFIX}/lib)
if(PCRE2_INCLUDE_DIR AND PCRE2_LIB)
  set(HAVE_PCRE2 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "PCRE2 ")
  include_directories(SYSTEM ${PCRE2_INCLUDE_DIR})
endif()
find_path(REMATCH_INCLUDE_DIR rematch/rematch.h HINTS ${CMAKE_INSTALL_PREFIX}/include)
find_library(REMATCHCOMP_LIB
  NAMES rematchcomp
  HINTS ${CMAKE_INSTALL_PREFIX}/lib)
find_library(REMATCHEXEC_LIB
  NAMES rematchexec
  HINTS ${CMAKE_INSTALL_PREFIX}/lib)
if(REMATCH_INCLUDE_DIR AND
   REMATCHCOMP_LIB AND REMATCHEXEC_LIB)
  set(HAVE_REMATCH 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "REmatch ")
  include_directories(SYSTEM ${REMATCH_INCLUDE_DIR})
endif()
find_path(RE2_INCLUDE_DIR re2/re2.h HINTS ${REMATCH_INCLUDE_DIR})
find_library(RE2_LIB
  NAMES re2
  HINTS ${CMAKE_INSTALL_PREFIX}/lib)
if(RE2_INCLUDE_DIR AND RE2_LIB)
  set(HAVE_RE2 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "RE2 ")
  include_directories(SYSTEM ${RE2_INCLUDE_DIR})
endif()

set(AVAIL_ENGS ${AVAIL_ENGS} "std::regex Boost::regex")

MESSAGE(STATUS "AVAILABLE ENGINES: " ${AVAIL_ENGS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# suppress warnings
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-disabled-macro-expansion")
endif()

if(Boost_INCLUDE_DIR)
  include_directories(SYSTEM ${Boost_INCLUDE_DIR})
endif()

subdirs(src)
