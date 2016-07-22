#include <sstream>

#include "BoostEngine.h"

using namespace regexbench;

void BoostEngine::compile(const std::vector<Rule> &rules) {
  std::stringstream msg;
  for (const auto &rule : rules) {
    boost::regex_constants::syntax_option_type op =
        boost::regex_constants::optimize;

    if (rule.isSet(MOD_CASELESS)) {
      op |= boost::regex_constants::icase;
    }
    if (rule.isSet(MOD_DOTALL)) {
      op |= boost::regex_constants::mod_s;
    }

    std::unique_ptr<boost::regex> re;
    try {
      re = std::make_unique<boost::regex>(rule.getRegexp().data());
    } catch (...) {
      msg << rule.getID() << " " << rule.getRegexp() << "\n";
      continue;
    }
    res.push_back(std::move(re));
  }
  if (msg.str().size()) {
    std::runtime_error error(msg.str());
    throw error;
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
