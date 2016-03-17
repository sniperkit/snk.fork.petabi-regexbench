// -*- c++ -*-
#ifndef REGEXBENCH_REMATCHENGINE_H
#define REGEXBENCH_REMATCHENGINE_H

#include <rematch/compile.h>

#include "Engine.h"

namespace regexbench {

class REmatchEngine : public Engine {
public:

  virtual void compile(const std::vector<Rule> &);
  virtual bool match(const char *, size_t) const;

private:
  mregex_t *txtbl;
};

} // namespace regexbench

#endif
