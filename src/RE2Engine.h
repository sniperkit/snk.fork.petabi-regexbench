// -*- c++ -*-
#ifndef REGEXBENCH_RE2ENGINE_H
#define REGEXBENCH_RE2ENGINE_H

#include <vector>
#include <re2/re2.h>

#include "Engine.h"

namespace regexbench {

class RE2Engine : public Engine {
public:
  RE2Engine();
  virtual ~RE2Engine();

  virtual void compile(const std::vector<Rule> &);
  virtual bool match(const char *, size_t);
private:
  std::vector<std::unique_ptr<re2::RE2>> res;
};

} // namespace regexbench

#endif
