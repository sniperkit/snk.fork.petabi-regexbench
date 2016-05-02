#include <rematch/compile.h>
#include "PCRE2Engine.h"

using namespace regexbench;

void PCRE2Engine::compile(const std::vector<Rule> &rules) {
  PCRE2_SIZE erroffset = 0;
  int errcode = 0;
  for (const auto &rule : rules) {
    auto re = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(rule.getRegexp().data()),
                         PCRE2_ZERO_TERMINATED, convert_to_pcre2_options(rule),
                         &errcode, &erroffset, nullptr);
    if (re == nullptr)
      throw std::runtime_error("PCRE2 Compile failed.");
    auto mdata = pcre2_match_data_create_from_pattern(re, nullptr);
    res.push_back(std::make_unique<PCRE2Engine::PCRE2_DATA>(re, mdata));
  }
}

uint32_t PCRE2Engine::convert_to_pcre2_options(const Rule &rule) {
  uint32_t opt = 0;
  if (rule.isSet(REMATCH_MOD_CASELESS))
    opt |= PCRE2_CASELESS;
  if (rule.isSet(REMATCH_MOD_MULTILINE))
    opt |= PCRE2_MULTILINE;
  if (rule.isSet(REMATCH_MOD_DOTALL))
    opt |= PCRE2_DOTALL;
  return opt;
}

bool PCRE2Engine::match(const char *data, size_t len) {
  for (const auto &re : res) {
    int rc = pcre2_match(re->re,
                         reinterpret_cast<PCRE2_SPTR>(data),
                         len, 0, PCRE2_NOTEMPTY_ATSTART |
                         PCRE2_NOTEMPTY,
                         re->mdata, nullptr);
    if (rc >=0)
      return true;
  }
  return false;
}
