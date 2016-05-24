// -*- c++ -*-
#ifndef REGEXBENCH_PCRE2_H
#define REGEXBENCH_PCRE2_H

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "Engine.h"

namespace regexbench {

class PCRE2Engine : public Engine {
public:
  PCRE2Engine() = default;
  virtual ~PCRE2Engine() = default;

  virtual void compile(const std::vector<Rule> &);
  virtual bool match(const char *, size_t);

protected:
  struct PCRE2_DATA {
    pcre2_code *re;
    pcre2_match_data *mdata;
    PCRE2_DATA(pcre2_code *re_, pcre2_match_data *mdata_) : re{re_}, mdata{mdata_} {}
    ~PCRE2_DATA() {
      pcre2_code_free(re);
      pcre2_match_data_free(mdata);
    }
  };

  std::vector<std::unique_ptr<PCRE2_DATA>> res;
};

class PCRE2JITEngine : public PCRE2Engine {
public:
  PCRE2JITEngine() = default;
  virtual ~PCRE2JITEngine() = default;

  virtual void compile(const std::vector<Rule> &);
};

} // namespace regexbench

#endif
