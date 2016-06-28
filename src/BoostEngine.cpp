#include "BoostEngine.h"

using namespace regexbench;

void BoostEngine::compile(const std::vector<Rule> &rules) {
  for (const auto &rule : rules) {
    // std::regex_constants::syntax_option_type op;

    // if (rule.isSet(MOD_CASELESS)) {
    //   op |= std::regex_constants::icase;
    // }

    auto re = std::make_unique<boost::regex>(rule.getRegexp().data());
    res.push_back(std::move(re));
  }
}


size_t BoostEngine::match(const char *data, size_t, size_t) {
  boost::cmatch m;
  for (const auto &re : res) {
    if (boost::regex_search(data, m, *re))
      return 1;
  }
  return 0;
}
