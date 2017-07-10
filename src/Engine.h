// -*- c++ -*-
#ifndef REGEXBENCH_ENGINE_H
#define REGEXBENCH_ENGINE_H

#include <map>
#include <set>
#include <vector>

#include "Rule.h"

namespace regexbench {

using match_rule_offset = std::map<size_t, std::set<std::pair<size_t, size_t>>>;

class Engine;

typedef struct {
  Engine* eng;
  size_t count;
  match_rule_offset* resMap;
} result_type;

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

protected:
  size_t numThreads = 1;
  const uint32_t nmatch = 0;

  // common callback signature (originally from hyperscan) to be used for
  // rematch2 and hyperscan
  static int onMatchCallback(unsigned id, unsigned long long from,
                             unsigned long long to, unsigned flags, void* ctx);
};

} // namespace regexbench

#endif
