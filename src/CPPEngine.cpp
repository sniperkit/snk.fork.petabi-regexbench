#include "CPPEngine.h"

using namespace regexbench;

void CPPEngine::compile(const std::vector<Rule> &rules) {
  for (const auto &rule : rules) {
    std::regex_constants::syntax_option_type op;

    if (rule.isSet(MOD_CASELESS)) {
      op |= std::regex_constants::icase;
    }

    auto re = std::make_unique<std::regex>(rule.getRegexp().data(), op);
    res.push_back(std::move(re));
  }
}


size_t CPPEngine::match(const char *data, size_t, size_t) {
  std::cmatch m;
  for (const auto &re : res) {
    if (std::regex_search(data, m, *re))
      return 1;
  }
  return 0;
}
