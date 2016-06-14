// -*- c++ -*-
#ifndef REGEXBENCH_RE2ENGINE_H
#define REGEXBENCH_RE2ENGINE_H

#include <vector>
#include <re2/re2.h>

#include "Engine.h"

namespace regexbench {

class RE2Engine : public Engine {
public:
  RE2Engine() = default;
  virtual ~RE2Engine() = default;

  virtual void compile(const std::vector<Rule> &);
  virtual size_t match(const char *, size_t);
private:
  std::vector<std::unique_ptr<re2::RE2>> res;
};

} // namespace regexbench

#endif
