// -*- c++ -*-
#ifndef REGEXBENCH_PCRE_H
#define REGEXBENCH_PCRE_H

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "Engine.h"

namespace regexbench {

class PCREEngine : public Engine {
public:
  PCREEngine();
  virtual ~PCREEngine();

  virtual void compile(const std::vector<Rule> &);
  virtual bool match(const char *, size_t);

private:
  std::vector<pcre2_code *>res;
  pcre2_match_data *pcre_matching_data;
};

} // namespace regexbench

#endif
