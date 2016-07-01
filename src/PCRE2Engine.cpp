#include "PCRE2Engine.h"

using namespace regexbench;

void PCRE2Engine::init(size_t mode) { isConcat = mode; }

void PCRE2Engine::concatCompile(std::string ruleStr, size_t nrules,
                                size_t offset, uint32_t ops) {
  PCRE2_SIZE erroffset = 0;
  int errcode = 0;
  auto re =
      pcre2_compile(reinterpret_cast<PCRE2_SPTR>(ruleStr.data()),
                    PCRE2_ZERO_TERMINATED, ops, &errcode, &erroffset, nullptr);
  if (re == nullptr) {
    if (nrules == 1 || errcode != 120)
      throw std::runtime_error("PCRE2 Compile failed.");

    auto splitOft = ruleOffset[offset + nrules / 2] - ruleOffset[offset];
    concatCompile(ruleStr.substr(0, splitOft - 1), nrules / 2, offset, ops);
    concatCompile(ruleStr.substr(splitOft), nrules / 2 + (nrules & 1),
                  offset + nrules / 2, 0);
  } else {
    auto mdata = pcre2_match_data_create_from_pattern(re, nullptr);
    res.push_back(std::make_unique<PCRE2Engine::PCRE2_DATA>(re, mdata));
    return;
  }
}

void PCRE2Engine::compile(const std::vector<Rule> &rules) {
  if (isConcat) {
    auto ruleSize = rules.size();
    auto ops = buildRuleOffset(const_cast<std::vector<Rule> &>(rules));
    concatCompile(rules[0].getRegexp(), ruleSize, 0, ops);
    return;
  }

  PCRE2_SIZE erroffset = 0;
  int errcode = 0;
  for (const auto &rule : rules) {
    auto re =
        pcre2_compile(reinterpret_cast<PCRE2_SPTR>(rule.getRegexp().data()),
                      PCRE2_ZERO_TERMINATED, rule.getPCRE2Options(), &errcode,
                      &erroffset, nullptr);
    if (re == nullptr)
      throw std::runtime_error("PCRE2 Compile failed.");
    auto mdata = pcre2_match_data_create_from_pattern(re, nullptr);
    res.push_back(std::make_unique<PCRE2Engine::PCRE2_DATA>(re, mdata));
  }
}

size_t PCRE2Engine::match(const char *data, size_t len, size_t) {
  for (const auto &re : res) {
    int rc = pcre2_match(re->re, reinterpret_cast<PCRE2_SPTR>(data), len, 0,
                         PCRE2_NOTEMPTY_ATSTART | PCRE2_NOTEMPTY, re->mdata,
                         nullptr);
    if (rc >= 0)
      return 1;
  }
  return 0;
}

void PCRE2JITEngine::compile(const std::vector<Rule> &rules) {
  PCRE2_SIZE erroffset = 0;
  int errcode = 0;

  for (const auto &rule : rules) {
    auto re =
        pcre2_compile(reinterpret_cast<PCRE2_SPTR>(rule.getRegexp().data()),
                      PCRE2_ZERO_TERMINATED, rule.getPCRE2Options(), &errcode,
                      &erroffset, nullptr);
    if (re == nullptr)
      throw std::runtime_error("PCRE2 Compile failed.");

    errcode = pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
    if (errcode < 0)
      throw std::runtime_error("PCRE2 JIT compile failed.");

    auto mdata = pcre2_match_data_create_from_pattern(re, nullptr);
    res.push_back(std::make_unique<PCRE2Engine::PCRE2_DATA>(re, mdata));
  }
}

uint32_t PCRE2Engine::buildRuleOffset(std::vector<Rule> &rules) {
  uint32_t ops = 0;
  size_t ruleOft = 0;
  std::string concatResult;
  for (const auto &rule : rules) {
    concatResult += "(";
    concatResult += rule.getRegexp();
    concatResult += ")|";
    ops |= rule.getPCRE2Options();
    ruleOffset.emplace_back(ruleOft);
    ruleOft = concatResult.size();
  }

  rules.clear();
  concatResult.resize(concatResult.size() - 1);
  rules.emplace_back(Rule(concatResult, 0, ops));
  return ops;
}
