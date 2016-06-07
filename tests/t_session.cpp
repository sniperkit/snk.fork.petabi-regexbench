#include <atf-c++.hpp>

#include <iostream>

#include "../src/session.h"
#include "../src/regexbench.h"
#include "../src/REmatchEngine.h"

using namespace regexbench;

ATF_TEST_CASE_WITHOUT_HEAD(session);
ATF_TEST_CASE_BODY(session) {
  REmatchAutomataEngineSession engine;
  engine.compile(regexbench::loadRules(DATA_DIR "/rule/session.re"));
  size_t nsessions = 0;
  regexbench::PcapSource pcap(DATA_DIR "/pcap/session.pcap");
  auto match_info = buildMatchMeta(pcap, nsessions);
  engine.init(nsessions);
  regexbench::MatchResult result = sessionMatch(engine, pcap, 1, match_info);
  ATF_REQUIRE_EQ(1, result.nmatches);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, session);
}

// int main() {
//   REmatchAutomataEngineSession engine;
//   engine.compile(regexbench::loadRules(DATA_DIR "/rule/session.re"));
//   std::cout << DATA_DIR << "\n";
//   size_t nsessions = 0;
//   regexbench::PcapSource pcap(DATA_DIR "/pcap/sniffles.pcap");
//   auto match_info = buildMatchMeta(pcap, nsessions);
//   std::cout << nsessions << "\n";
//   engine.init(nsessions);

  
//   regexbench::MatchResult result = sessionMatch(engine, pcap, 1, match_info);

//   std::cout << result.nmatches << " " << nsessions <<  "\n";
  
//   // ATF_REQUIRE_EQ(1, result.nmatches);

// }
