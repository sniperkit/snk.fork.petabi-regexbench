// -*- c++ -*-
#ifndef REGEXBENCH_PCRE2_H
#define REGEXBENCH_PCRE2_H

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "Engine.h"

namespace regexbench {

class PCRE2Engine : public Engine {
public:
  PCRE2Engine();
  virtual ~PCRE2Engine();

  virtual void compile(const std::vector<Rule> &);
  virtual bool match(const char *, size_t);

private:
  std::vector<std::unique_ptr<pcre2_code, std::function<void(pcre2_code*)>>> res;
  pcre2_match_data *pcre_matching_data;
  uint32_t convert_to_pcre2_options(const Rule &);
};

} // namespace regexbench

#endif
