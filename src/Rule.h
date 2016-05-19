// -*- c++ -*-
#ifndef REGEXBENCH_RULE_H
#define REGEXBENCH_RULE_H

#include <bitset>
#include <cstdint>
#include <istream>
#include <string>
#include <vector>

namespace regexbench {

enum Modifier : unsigned {
  MOD_CASELESS, MOD_MULTILINE, MOD_DOTALL,
  NMODS
};

class Rule {
public:
  Rule() = delete;
  Rule(const Rule &) = default;
  Rule(Rule &&) = default;
  explicit Rule(const std::string &);
  explicit Rule(const std::string &, size_t);
  ~Rule() = default;
  Rule &operator=(const Rule &) = default;
  Rule &operator=(Rule &&) = default;

  size_t getID() const { return id; }
  uint32_t getPCRE2Options() const;
  const std::string &getRegexp() const { return regexp; }
  bool isSet(unsigned mod) const { return mods[mod]; }
  void swapRegexp(std::string &other) { regexp.swap(other); }

private:
  void parseRule(const std::string &, size_t);

  size_t id;
  std::string regexp;
  std::bitset<NMODS> mods;
};

std::vector<Rule> loadRules(std::istream &);
void concatRules(std::vector<Rule> &);

} // namespace regexbench

#endif
