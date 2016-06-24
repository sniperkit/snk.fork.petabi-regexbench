#include <atf-c++.hpp>

#include <iostream>

#include "../src/Session.h"
#include "../src/regexbench.h"
#include "../src/REmatchEngine.h"

using namespace regexbench;

ATF_TEST_CASE_WITHOUT_HEAD(session1);
ATF_TEST_CASE_BODY(session1) {
  REmatchAutomataEngineSession engine;
  engine.compile(regexbench::loadRules(DATA_DIR "/rule/session.re"));
  size_t nsessions = 0;
  regexbench::PcapSource pcap(DATA_DIR "/pcap/session.pcap");
  auto match_info = buildMatchMeta(pcap, nsessions);
  engine.init(nsessions);
  regexbench::MatchResult result = match(engine, pcap, 1, match_info);
  ATF_REQUIRE_EQ(1, result.nmatches);
}

ATF_TEST_CASE_WITHOUT_HEAD(session2);
ATF_TEST_CASE_BODY(session2) {
  REmatchAutomataEngineSession engine;
  engine.compile(regexbench::loadRules(DATA_DIR "/rule/session2.re"));
  size_t nsessions = 0;
  regexbench::PcapSource pcap(DATA_DIR "/pcap/session2.pcap");
  auto match_info = buildMatchMeta(pcap, nsessions);
  ATF_REQUIRE_EQ(4, nsessions);
  engine.init(nsessions);
  regexbench::MatchResult result = match(engine, pcap, 1, match_info);
  ATF_REQUIRE_EQ(2, result.nmatches);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, session1);
  ATF_ADD_TEST_CASE(tcs, session2);
}
