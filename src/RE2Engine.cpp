#include "RE2Engine.h"

#include <rematch/compile.h>
using namespace regexbench;

RE2Engine::RE2Engine() = default;

RE2Engine::~RE2Engine() = default;

void RE2Engine::compile(const std::vector<Rule> &rules) {
  for (const auto &rule : rules) {
    RE2::Options op;

    if (rule.isSet(REMATCH_MOD_CASELESS)) {
      op.set_case_sensitive(false);
    }
    if (rule.isSet(REMATCH_MOD_MULTILINE)) {
      op.set_one_line(false);
    }
    if (rule.isSet(REMATCH_MOD_DOTALL)) {
      op.set_dot_nl(true);
    }

    res.push_back(std::make_unique<re2::RE2>(rule.getRegexp(), op));
  }
}

bool RE2Engine::match(const char *data, size_t len) {
  len = 0;
  for (const auto &re : res) {
    if (re2::RE2::PartialMatch(data, *re)) {
      return true;
    }
  }
  return false;
}
