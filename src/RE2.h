// -*- c++ -*-
#ifndef REGEXBENCH_RE2_H
#define REGEXBENCH_RE2_H

#include "Engine.h"

namespace regexbench {

class RE2 : public Engine {
public:
  RE2();
  virtual ~RE2();

  virtual void compile(const std::vector<Rule> &);
  virtual bool match(const char *, size_t);

private:
};

} // namespace regexbench

#endif
