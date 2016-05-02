#include "RE2Engine.h"

using namespace regexbench;

RE2Engine::RE2Engine() = default;

RE2Engine::~RE2Engine() = default;

void RE2Engine::compile(const std::vector<Rule> &rules) {
  RE2::Options op;
  op.set_dot_nl(true);
  op.set_case_sensitive(false);
  op.set_one_line(false);

  for (const auto &rule : rules) {
    res.push_back(std::unique_ptr<RE2>(new RE2{rule.getRegexp().data(), op}));
  }
}

bool RE2Engine::match(const char *data, size_t len) {
  len = 0;
  for (const auto &re : res) {
    if (RE2::FullMatch(data, *re))
      return true;
  }
  return false;
}


