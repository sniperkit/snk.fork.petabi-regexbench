#include <atf-c++.hpp>

#include <iostream>

#include "../src/BoostEngine.h"
#include "../src/CPPEngine.h"
#include "../src/HyperscanEngine.h"
#include "../src/PcapSource.h"
#include "../src/PCRE2Engine.h"
#include "../src/RE2Engine.h"
#include "../src/regexbench.h"
#include "../src/REmatchEngine.h"

using namespace regexbench;

regexbench::MatchResult opTest(Engine *engine) {
  engine->compile(regexbench::loadRules(DATA_DIR "/rule/option.re"));
  size_t nsessions = 0;
  regexbench::PcapSource pcap(DATA_DIR "/pcap/option.pcap");
  auto match_info = buildMatchMeta(pcap, nsessions);
  engine->init(nsessions);
  return regexbench::match(*engine, pcap, 1, match_info);
}

ATF_TEST_CASE_WITHOUT_HEAD(t_option);
ATF_TEST_CASE_BODY(t_option) {
  regexbench::MatchResult result;

  BoostEngine bengine;
  result = opTest(&bengine);
  ATF_REQUIRE_EQ(3, result.nmatches);

  CPPEngine cengine;
  result = opTest(&cengine);
  ATF_REQUIRE_EQ(2, result.nmatches);

  HyperscanEngine hsengine;
  result = opTest(&hsengine);
  ATF_REQUIRE_EQ(3, result.nmatches);

  PCRE2Engine pengine;
  result = opTest(&pengine);
  ATF_REQUIRE_EQ(3, result.nmatches);

  RE2Engine re2engine;
  result = opTest(&re2engine);
  ATF_REQUIRE_EQ(3, result.nmatches);

  REmatchAutomataEngine rengine;
  result = opTest(&rengine);
  ATF_REQUIRE_EQ(3, result.nmatches);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, t_option);
}
