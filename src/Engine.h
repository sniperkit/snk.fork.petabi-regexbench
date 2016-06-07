// -*- c++ -*-
#ifndef REGEXBENCH_ENGINE_H
#define REGEXBENCH_ENGINE_H

#include <vector>

#include "Rule.h"
#include "PcapSource.h"
#include "session.h"

namespace regexbench {

class Engine {
public:
  virtual ~Engine();

  virtual void compile(const std::vector<Rule> &) {}
  virtual void init(size_t) {}
  virtual void load(const std::string &) {}
  virtual bool match(const char *, size_t) = 0;
  virtual bool match(const char *, size_t, size_t) { return false; }
};

} // namespace regexbench

#endif
