#include "config.h"

#include <atf-c++.hpp>

#include <iostream>

#include "../src/regexbench.h"
#ifdef HAVE_RE2
#include "../src/RE2Engine.h"
#endif
#include "../src/PcapSource.h"

using namespace regexbench;

ATF_TEST_CASE_WITHOUT_HEAD(rule_compile);
ATF_TEST_CASE_BODY(rule_compile)
{
#ifdef HAVE_RE2
  RE2Engine engine;
  ATF_REQUIRE_THROW(std::runtime_error, engine.compile(regexbench::loadRules(
                                            DATA_DIR "/rule/malformat.re")););
#endif
}

ATF_INIT_TEST_CASES(tcs) { ATF_ADD_TEST_CASE(tcs, rule_compile); }
