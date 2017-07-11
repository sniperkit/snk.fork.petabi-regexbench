// -*- c++ -*-
#ifndef REGEXBENCH_H
#define REGEXBENCH_H

#include "Engine.h"
#include "Logger.h"
#include "Rule.h"

#include <atomic>
#include <boost/timer/timer.hpp>
#include <map>
#include <memory>
#include <vector>

enum class EngineType : uint64_t {
  boost,
  std_regex,
  hyperscan,
  pcre2,
  pcre2_jit,
  re2,
  rematch,
  rematch2,
  unknown
};

struct Arguments {
  std::string output_file;
  std::string detail_file;
  std::string log_file;
  std::string pcap_file;
  std::string rule_file;
  std::string update_pipe;
  std::string compile_time;
  EngineType engine;
  int32_t repeat;
  uint32_t pcre2_concat;
  uint32_t rematch_session;
  uint32_t num_threads;
  uint32_t compile_test;
  uint32_t nmatch = 0;
  std::vector<size_t> cores;
  bool reduce = {false};
  bool quiet = {false};
#ifdef USE_TURBO
  bool turbo = {false};
  char paddings[5];
#else
  char paddings[6];
#endif
};

namespace regexbench {

class Engine;
class PcapSource;

struct ResultInfo {
  ResultInfo() : nmatches(0), nmatched_pkts(0), npkts(0), nbytes(0) {}
  size_t nmatches;
  size_t nmatched_pkts;
  size_t npkts;
  size_t nbytes;
};

struct MatchResult {
  MatchResult() : stop(false) {}
  MatchResult(const MatchResult& s)
  {
    udiff = s.udiff;
    sdiff = s.sdiff;
    cur = s.cur;
    old = s.old;
    stop.store(s.stop.load());
  }

  MatchResult& operator=(const MatchResult& rhs)
  {
    if (this == &rhs)
      return *this;
    udiff = rhs.udiff;
    sdiff = rhs.sdiff;
    cur = rhs.cur;
    old = rhs.old;
    stop.store(rhs.stop.load());
    return *this;
  }

  struct timeval udiff;
  struct timeval sdiff;
  struct ResultInfo cur;
  struct ResultInfo old;
  // detailed result :
  //  map of pkt # =>
  //    map of rule id => set of match offset (inside a packet) pair
  std::map<size_t, match_rule_offset> detail;
  std::atomic_bool stop;
  char paddings[7];
};

struct MatchMeta {
  MatchMeta(size_t sid_ = 0, size_t oft_ = 0, size_t len_ = 0)
      : sid(sid_), oft(oft_), len(len_)
  {
  }
  bool operator==(const MatchMeta& rhs)
  {
    return sid == rhs.sid && oft == rhs.oft && len == rhs.len;
  }
  size_t sid;
  size_t oft;
  size_t len;
};

typedef void (*realtimeFunc)(const std::map<std::string, size_t>&, void* p);

int setAffinity(size_t core, const std::string& thrName = "");
std::vector<MatchMeta> buildMatchMeta(const PcapSource&, size_t&);
uint32_t getPLOffset(const std::string&);
std::vector<Rule> loadRules(const std::string&);
void matchThread(Engine* engine, const PcapSource* src, long repeat,
                 size_t core, size_t sel, const std::vector<MatchMeta>* meta,
                 MatchResult* result, Logger* logger);
std::vector<MatchResult> match(Engine&, const PcapSource&, long,
                               const std::vector<size_t>&,
                               const std::vector<MatchMeta>&,
                               const std::string&, realtimeFunc func = nullptr,
                               void* p = nullptr);
void realtimeReport(const std::map<std::string, size_t>& m, void* p = nullptr);
std::string compileReport(const struct rusage& compileBegin,
                          const struct rusage& compileEnd,
                          const PcapSource& pcap, bool quiet);
void report(std::string& prefix, const PcapSource& pcap, const Arguments& args,
            const std::vector<MatchResult>& results);
Arguments init(const std::string& rule_file, const std::string& pcap_file,
               const std::string& output_file,
               const std::string& engine = "hyperscan", uint32_t nthreads = 1,
               const std::string& affinity = "0", int32_t repeat = 1);
int exec(Arguments& args, realtimeFunc func = nullptr, void* p = nullptr);
Arguments parse_options(int argc, const char* argv[]);
void statistic(const uint32_t sec, std::vector<MatchResult>& results,
               realtimeFunc func = nullptr, void* p = nullptr);
std::unique_ptr<Engine> loadEngine(Arguments& args, std::string& prefix,
                                   size_t nsessions);
}

#endif // REGEXBENCH_H
