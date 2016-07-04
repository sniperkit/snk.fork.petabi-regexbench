// -*- c++ -*-
#ifndef REGEXBENCH_BOOSTENGINE_H
#define REGEXBENCH_BOOSTENGINE_H

#include <boost/regex.hpp>
#include <vector>

#include "Engine.h"

namespace regexbench {

class BoostEngine : public Engine {
public:
  BoostEngine() = default;
  virtual ~BoostEngine() = default;

  virtual void compile(const std::vector<Rule> &);
  virtual size_t match(const char *, size_t, size_t);

private:
  std::vector<std::unique_ptr<boost::regex>> res;
};

} // namespace regexbench

#endif
