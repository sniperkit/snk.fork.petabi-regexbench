#include <atf-c++.hpp>

#include <iostream>

#include "../src/HyperscanEngine.h"
#include "../src/PcapSource.h"
#include "../src/PCRE2Engine.h"
#include "../src/RE2Engine.h"
#include "../src/regexbench.h"
#include "../src/REmatchEngine.h"

using namespace regexbench;

void opTest(Engine *engine) {
  engine->compile(regexbench::loadRules(DATA_DIR "/rule/option.re"));
  size_t nsessions = 0;
  regexbench::PcapSource pcap(DATA_DIR "/pcap/option.pcap");
  auto match_info = buildMatchMeta(pcap, nsessions);
  engine->init(nsessions);
  regexbench::MatchResult result = regexbench::match(*engine, pcap, 1, match_info);
  ATF_REQUIRE_EQ(3, result.nmatches);
}

ATF_TEST_CASE_WITHOUT_HEAD(t_option);
ATF_TEST_CASE_BODY(t_option) {
  RE2Engine re2engine;
  opTest(&re2engine);

  HyperscanEngine hsengine;
  opTest(&hsengine);

  REmatchAutomataEngine rengine;
  opTest(&rengine);

  PCRE2Engine pengine;
  opTest(&pengine);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, t_option);
}
