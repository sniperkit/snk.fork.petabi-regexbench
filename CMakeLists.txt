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

find_package(Boost REQUIRED COMPONENTS program_options regex system)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIB pcap)

find_library(ATF_LIB atf-c++)

if(ATF_LIB)
  subdirs(tests)
endif()

find_path(HYPERSCAN_INCLUDE_DIR hs/hs_compile.h)
find_library(HYPERSCAN_LIB hs)
if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIB)
  set(HAVE_HYPERSCAN 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "Hyperscan ")
endif()
find_path(PCRE2_INCLUDE_DIR pcre2.h)
find_library(PCRE2_LIB pcre2-8)
if(PCRE2_INCLUDE_DIR AND PCRE2_LIB)
  set(HAVE_PCRE2 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "PCRE2 ")
endif()
find_path(REMATCH_INCLUDE_DIR rematch/rematch.h)
find_library(REMATCHCOMP_LIB rematchcomp)
find_library(REMATCHEXEC_LIB rematchexec)
if(REMATCH_INCLUDE_DIR AND
    REMATCHCOMP_LIB AND REMATCHEXEC_LIB)
  set(HAVE_REMATCH 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "REmatch ")
endif()
find_path(RE2_INCLUDE_DIR re2/re2.h)
find_library(RE2_LIB re2)
if(RE2_INCLUDE_DIR AND RE2_LIB)
  set(HAVE_RE2 1)
  set(AVAIL_ENGS ${AVAIL_ENGS} "RE2 ")
endif()

set(AVAIL_ENGS ${AVAIL_ENGS} "std::regex Boost::regex")

MESSAGE(STATUS "AVAILABLE ENGINES: " ${AVAIL_ENGS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# suppress warnings

if(HAVE_PCRE2)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-disabled-macro-expansion")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-reserved-id-macro")
endif()

if(Boost_INCLUDE_DIR)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-sign-conversion")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-weak-vtables")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-documentation-unknown-command")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-padded")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-exit-time-destructors")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-switch-enum")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-old-style-cast")
endif()

if(HAVE_HYPERSCAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-documentation")
endif()

if(HAVE_RE2)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-extra-semi")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-padded")
endif()

subdirs(src)
