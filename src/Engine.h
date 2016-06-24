// -*- c++ -*-
#ifndef REGEXBENCH_ENGINE_H
#define REGEXBENCH_ENGINE_H

#include <vector>

#include "Rule.h"

namespace regexbench {

class Engine {
public:
  virtual ~Engine();

  virtual void compile(const std::vector<Rule> &) {}
  virtual void init(size_t) {}
  virtual void load(const std::string &) {}
  virtual size_t match(const char *, size_t, size_t) = 0;
};

} // namespace regexbench

#endif
