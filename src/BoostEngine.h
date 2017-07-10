// -*- c++ -*-
#ifndef REGEXBENCH_BOOSTENGINE_H
#define REGEXBENCH_BOOSTENGINE_H

#include <boost/regex.hpp>
#include <vector>

#include "Engine.h"

namespace regexbench {

class BoostEngine : public Engine {
public:
  BoostEngine(uint32_t nm = 1) : Engine(nm) {}
  virtual ~BoostEngine() = default;

  virtual void compile(const std::vector<Rule>&, size_t);
  virtual size_t match(const char*, size_t, size_t, size_t = 0,
                       match_rule_offset* = nullptr);

private:
  std::vector<std::unique_ptr<boost::regex>> res;
};

} // namespace regexbench

#endif
