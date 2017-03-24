#ifndef NDEBUG
#include <iostream>
#endif
#include <stdexcept>
#include <string>

#include <boost/algorithm/string/trim.hpp>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "Rule.h"

using namespace regexbench;

Rule::Rule(const std::string& rule)
{
  auto colon_pos = rule.find(':');
  if (colon_pos == rule.npos)
    throw std::invalid_argument("no rule ID in the rule");
  size_t invalid_pos;
  id = std::stoul(rule, &invalid_pos);
  if (invalid_pos != colon_pos)
    throw std::invalid_argument("invalid ID");
  parseRule(rule, colon_pos + 1);
}

Rule::Rule(const std::string& rule, size_t ruleid, uint32_t ops) : id(ruleid)
{
  parseRule(rule, 0);
  if (ops)
    setOptions(ops);
}

void Rule::setOptions(uint32_t pcre2ops)
{
  if (pcre2ops & PCRE2_CASELESS)
    mods.set(MOD_CASELESS);
  if (pcre2ops & PCRE2_MULTILINE)
    mods.set(MOD_MULTILINE);
  if (pcre2ops & PCRE2_DOTALL)
    mods.set(MOD_DOTALL);
}

uint32_t Rule::getPCRE2Options() const
{
  uint32_t opt = 0;
  if (isSet(MOD_CASELESS))
    opt |= PCRE2_CASELESS;
  if (isSet(MOD_MULTILINE))
    opt |= PCRE2_MULTILINE;
  if (isSet(MOD_DOTALL))
    opt |= PCRE2_DOTALL;
  return opt;
}

void Rule::parseRule(const std::string& rule, size_t left_delim_pos)
{
  if (left_delim_pos == rule.size())
    throw std::invalid_argument("no regexp in the rule");
  if (rule[left_delim_pos] != '/') {
    regexp = rule.substr(left_delim_pos);
    return;
  }
  auto right_delim_pos = rule.rfind(rule[left_delim_pos]);
  if (right_delim_pos == left_delim_pos) {
    regexp = rule.substr(left_delim_pos);
    return;
  }
  regexp =
      rule.substr(left_delim_pos + 1, right_delim_pos - left_delim_pos - 1);
  for (auto i = right_delim_pos + 1; i < rule.size(); ++i)
    switch (rule[i]) {
    case 'i':
      mods.set(MOD_CASELESS);
      break;
    case 'm':
      mods.set(MOD_MULTILINE);
      break;
    case 's':
      mods.set(MOD_DOTALL);
      break;

    case 'A':
    /* PCRE_ANCHORED */
    case 'B':
    /* SNORT_PCRE_RAWBYTES */
    case 'C':
    case 'D':
    case 'E':
    /* PCRE_DOLLAR_ENDONLY */
    case 'G':
    /* PCRE_UNGREEDY */
    case 'H':
    case 'I':
    case 'K':
    case 'M':
    case 'O':
    /* SNORT_OVERRIDE_MATCH_LIMIT */
    case 'P':
    /* SNORT_PCRE_HTTP_BODY */
    case 'R':
    /* SNORT_PCRE_RELATIVE */
    case 'S':
    case 'U':
    /* SNORT_PCRE_HTTP_URI */
    case 'Y':
    case 'x':
/* PCRE_EXTENDED */
#ifndef NDEBUG
      std::cerr << "WARNING: Unsupported regex option: " << rule[i]
                << std::endl;
#endif
      break;
    default:
      throw std::invalid_argument("unknown option");
    }
}

std::vector<Rule> regexbench::loadRules(std::istream& is)
{
  std::vector<Rule> rules;
  try {
    for (std::string line; std::getline(is, line);) {
      boost::algorithm::trim(line);
      if (line.size() == 0 || line[0] == '#')
        continue;
      rules.emplace_back(Rule(line));
    }
  } catch (const std::invalid_argument&) {
    is.seekg(std::ios_base::beg);
  }
  if (is.tellg() != std::ios_base::beg)
    return rules;

  rules.clear();
  try {
    size_t id = 0;
    for (std::string line; std::getline(is, line);) {
      boost::algorithm::trim(line);
      if (line.size() == 0 || line[0] == '#')
        continue;
      rules.emplace_back(Rule(line, id++));
    }
  } catch (const std::invalid_argument&) {
    throw std::runtime_error("cannot parse rules");
  }
  return rules;
}
