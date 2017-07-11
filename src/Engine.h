// -*- c++ -*-
#ifndef REGEXBENCH_ENGINE_H
#define REGEXBENCH_ENGINE_H

#include <map>
#include <set>
#include <vector>

#include "Rule.h"

namespace regexbench {

// match information for each packet
// map of rule id to offset pairs at which matches have occurred
using match_rule_offset = std::map<size_t, std::set<std::pair<size_t, size_t>>>;

class Engine;

// callback context type that will be used for opaque context pointer
// delivered to match callback
typedef struct {
  Engine* eng;
  size_t count;
  match_rule_offset* resMap;
} cb_ctxt_type;

class Engine {
public:
  virtual ~Engine();
  Engine(uint32_t nm) : nmatch(nm) {}

  virtual void compile(const std::vector<Rule>&, size_t = 1) {}
  virtual void compile_test(const std::vector<Rule>&) const {}
  virtual void update_test(const std::vector<Rule>&) {}
  virtual void init(size_t) {}
  virtual size_t getNumThreads() { return numThreads; }
  virtual void load(const std::string&, size_t = 1) {}
  virtual size_t match(const char*, size_t, size_t, size_t = 0,
                       match_rule_offset* = nullptr) = 0;

  void setSaveDetail(bool set = true) { saveDetail = set ? 1 : 0; }
  bool isSaveDetail() { return saveDetail != 0; }

protected:
  size_t numThreads = 1;
  const uint32_t nmatch = 0;
  uint32_t saveDetail = 0;

  // common callback signature (originally from hyperscan) to be used for
  // rematch2 and hyperscan
  static int onMatchCallback(unsigned id, unsigned long long from,
                             unsigned long long to, unsigned flags, void* ctx);
};

} // namespace regexbench

#endif
