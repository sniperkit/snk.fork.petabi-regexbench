// -*- c++ -*-
#ifndef REGEXBENCH_ENGINE_H
#define REGEXBENCH_ENGINE_H

#include <vector>

#include "Rule.h"

namespace regexbench {

class Engine {
public:
  virtual ~Engine();

  virtual void compile(const std::vector<Rule> &) = 0;
  virtual bool match(const char *, size_t) = 0;
  virtual void load(const std::string &) = 0;
};

} // namespace regexbench

#endif
