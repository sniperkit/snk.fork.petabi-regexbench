// -*- c++ -*-
#ifndef REGEXBENCH_REMATCHENGINE_H
#define REGEXBENCH_REMATCHENGINE_H

#include <rematch/rematch.h>

#include "Engine.h"

namespace regexbench {

class REmatchEngine : public Engine {
public:
  REmatchEngine();
  virtual ~REmatchEngine();

  virtual void compile(const std::vector<Rule> &);
  virtual bool match(const char *, size_t);
  virtual void load(const std::string &);

private:
  mregflow_t *flow;
  matcher_t *matcher;
  mregex_t *txtbl;
  mregmatch_t regmatch[1];
};

} // namespace regexbench

#endif
