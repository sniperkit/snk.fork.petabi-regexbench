#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <string.h>

#include "CheckerShell.h"
#include "PcreChecker.h"
#include "litesql_helper.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;

using std::vector;

// pcre_check namespace aliases
using pcre_check::PcreCheckDb;
using DbRule = pcre_check::Rule;
using pcre_check::Pattern;
using pcre_check::Grammar;
using pcre_check::Engine;
using pcre_check::Result;
using pcre_check::Test;
using pcre_check::TestGrammar;
using pcre_check::TestResult;

// litesql namespace aliases
using litesql::select;
using litesql::Blob;
using litesql::Except;
using litesql::Expr;
using litesql::And;
using litesql::NotFound;
using litesql::Eq;
using litesql::NotEq;
using litesql::Split;

using CS = CheckerShell;

CS* CS::instance = nullptr;

void CS::initialize()
{
  el = el_init("CheckerShell", stdin, stdout, stderr);
  el_set(el, EL_PROMPT, &CS::prompt);
  el_set(el, EL_EDITOR, "emacs");

  // initialize the history
  hist = history_init();
  if (hist == nullptr) {
    throw std::runtime_error("Checker shell history init error");
  }

  // set the size of the history
  HistEvent histEv;
  history(hist, &histEv, H_SETSIZE, 100);
  // sets up the callback for history
  el_set(el, EL_HIST, history, hist);
  // for tab command completion
  el_set(el, EL_ADDFN, "complete", "command completion", &CS::complete);
  el_set(el, EL_BIND, "\t", "complete", nullptr);

  tok = tok_init(nullptr);
  cmdOpts[id::show][id::table].setExcl(); // one of rule, pattern, test
  cmdOpts[id::show][id::table][id::test][id::result][id::expect].setExcl();
  cmdOpts[id::show][id::table][id::test][id::result][id::engine].setExcl();
}

void CS::run()
{
  int count;
  const char* line;
  HistEvent histEv;
  running = 1;
  while (running) {
    line = el_gets(el, &count);

    if (count > 0 && line[0] != '\n') {
      history(hist, &histEv, H_ENTER, line);
      dispatchCmds(line);
    }
    tok_reset(tok);
  }
}

char* CS::prompt(EditLine*)
{
  static char prStr[16] = "PCREChk:$ ";
  return prStr; // shell prompt
}

unsigned char CS::complete(EditLine*, int /*ch*/)
{
  if (instance)
    return instance->doComplete();
  return CC_ERROR;
}

//
// extracts common string part from the list of strings
// and returns the length of the common string
//
static size_t getCommon(const std::vector<std::string>& cands,
                        std::string& common, size_t offset = 0)
{
  // caller should guarantee that [0, offset) range of every cands strings are
  // equal because this function assumes so
  size_t newLen = offset; // value to return
  auto szCands = cands.size();
  size_t ovrlap = offset;

  if (szCands < 1) { // just to be sure
    common = "";
    return 0;
  }
  if (szCands > 1) {
    ovrlap = cands[0].size();
  }
  for (size_t i = 0; i < szCands && (i + 1 < szCands); ++i) {
    ovrlap = std::min(std::min(cands[i].size(), cands[i + 1].size()), ovrlap);
    for (; ovrlap > offset; --ovrlap) {
      auto r = cands[i].compare(offset, ovrlap - offset, cands[i + 1], offset,
                                ovrlap - offset);
      if (r == 0)
        break;
    }
    if (ovrlap <= offset) {
      newLen = ovrlap;
      break;
    }
    newLen = ovrlap;
  }

  common = cands[0].substr(0, newLen);
  return newLen;
}

unsigned char CS::doComplete()
{
  static char line[LINE_MAX + 1]; // including null character
  static size_t lastCurpos = 0;
  static size_t lastLen = 0;
  static bool first = true;
  unsigned char ret = CC_REDISPLAY;
  const LineInfo* lf;
  bool list = false;
  int cmpl = 1; // complete last argument
  lf = el_line(el);

  size_t len = static_cast<size_t>(lf->lastchar - lf->buffer);
  size_t curpos = static_cast<size_t>(lf->cursor - lf->buffer);

  if (len > LINE_MAX)
    return CC_ERROR;

  if (curpos != len) // only supports when cursor is on last character
    return CC_ERROR;

  if ((!first && len == 0) ||
      (len > 0 && len == lastLen && lf->cursor == lf->lastchar &&
       curpos == lastCurpos && memcmp(line, lf->buffer, len) == 0))
    list = true;

  if (first)
    first = false;

  if (!list) {
    memcpy(line, lf->buffer, len);
    line[len] = '\0';
    lastLen = len;
    lastCurpos = static_cast<size_t>(lf->cursor - lf->buffer);
  }

  tok_reset(tok);
  cmdOpts.reset();
  int cmdsC;
  const char** cmds;

  if (len > 0) {
    int r = tok_str(tok, line, &cmdsC, &cmds);
    if (r != 0)
      return CC_ERROR;
    if (line[len - 1] == ' ') // new argument completion
      cmpl = 2;
    cCtx.reset(cmdsC, cmds, cmpl, list); // completion mode
  } else {
    cCtx.reset(0, nullptr, 2, list); // cmpletion mode 2 (new arg)
  }

  try {
    cmdOpts.parseCmdline(cCtx);
    auto szCmpl = cCtx.getSzCmpl();
    auto lenCmd = cCtx.getLenCmd(); // last command size
    std::string insertStr;
    if (szCmpl == 1) {
      insertStr = cCtx.getCmpl()[0];
      insertStr += " ";
      el_insertstr(el, insertStr.c_str() + lenCmd);
      ret = CC_REFRESH;
    } else if (szCmpl > 1) {
      auto lenCommon = getCommon(cCtx.getCmpl(), insertStr, lenCmd);
      if (lenCommon > lenCmd) {
        el_insertstr(el, insertStr.c_str() + lenCmd);
        ret = CC_REFRESH;
      }
      if (list && ret != CC_REFRESH) {
        std::cout << "\n";
        std::cout << "command candidates ...\n";
        for (auto& c : cCtx.getCmpl())
          std::cout << " " << c << "\n";
      }
    }
  } catch (std::runtime_error& /*ex*/) {
    ret = CC_ERROR;
  }

  return ret;
}

template <> void CS::processCmd(CS::cmd_attach_option& opt)
{
  if (neverAttached) {
    checker.detach(); // checker is attached to a temporary file automatically
    neverAttached = false;
  }

  if (!opt[id::db].isValid()) {
    cerr << "command incomplete : must specify db file" << endl;
    return;
  }

  std::string dbFile = opt[id::db]();
  if (checker.attach(dbFile) < 0) {
    cerr << "Already attached to a DB " << dbFile << endl;
    cerr << "Detach first" << endl;
    return;
  }
}

template <> void CS::processCmd(CS::cmd_detach_option& opt)
{
  checker.detach();
  cout << "DB detached" << endl;
}

template <> void CS::processCmd(CS::cmd_setup_option& opt)
{
  if (opt[id::from].isValid() && opt[id::from][id::json].isValid())
    try {
      checker.setupDb(opt[id::from][id::json]());
    } catch (const std::exception& e) {
      cerr << e.what() << endl;
      return;
    }
}

template <> void CS::processCmd(CS::cmd_update_option& opt)
{
  try {
    checker.checkDb();
  } catch (const std::exception& e) {
    cerr << e.what() << endl;
    return;
  }
}

template <> void CS::processCmd(CS::cmd_singletest_option& opt)
{
  if (!opt[id::re].isValid() || !opt[id::data].isValid()) {
    cerr << "'re' and 'data' should be specified" << endl;
    return;
  }

  if (!opt[id::ctype]().empty() && opt[id::ctype]() != "hex" &&
      opt[id::ctype]() != "str") {
    cerr << "'invalid content type(hex, str)" << endl;
    return;
  }

  std::string rule = opt[id::re]();
  std::string data = opt[id::data]();

  auto results = checker.checkSingle(
      rule, data, (!opt[id::ctype]().empty() && opt[id::ctype]() == "hex"));

  cout << "Result : rematch => " << results[0] << endl;
  cout << "Result : hyperscan => " << results[1] << endl;
  cout << "Result : pcre => " << results[2] << endl;
}

void CS::processTestTable(CS::cmd_show_table_test_option& opt)
{
  bool condFailed = false;
  bool showContent = opt[id::detailed].isValid() ? true : false;
  auto matchResult = // for reference
      select<Result>(checker.getDb(), Result::Name == "match").one();

  std::string condExpect, condEngine;
  Split queryFirst;

  if (opt[id::cond].isValid()) {
    auto& cond = opt[id::cond];
    if (cond[id::rule].isValid())
      queryFirst.push_back((DbRule::Name == cond[id::rule]()).asString());
    if (cond[id::pattern].isValid())
      queryFirst.push_back((Pattern::Name == cond[id::pattern]()).asString());
  }
  if (opt[id::result].isValid()) {
    auto& result = opt[id::result];
    if (result[id::failed].isValid())
      condFailed = true;
    if (result[id::expect].isValid()) {
      if (result[id::expect][id::match].isValid())
        condExpect = (Result::Name == "match").asString();
      if (result[id::expect][id::nomatch].isValid())
        condExpect = (Result::Name == "nomatch").asString();
      if (result[id::expect][id::error].isValid())
        condExpect = (Result::Name == "error").asString();
      if (!condExpect.empty())
        queryFirst.push_back(condExpect);
    }
    if (result[id::engine].isValid()) {
      if (result[id::engine][id::pcre].isValid())
        condEngine = (Engine::Name == "pcre").asString();
      if (result[id::engine][id::rematch].isValid())
        condEngine = (Engine::Name == "rematch").asString();
      if (result[id::engine][id::hyperscan].isValid())
        condEngine = (Engine::Name == "hyperscan").asString();
    }
  }

  JoinedSource<Test, DbRule, Pattern, Result> source(checker.getDb(),
                                                     true); // left join
  // result table can be empty (because expectid can be 0)
  source.joinCond(Eq(DbRule::Id, Test::Ruleid))
      .joinCond(Eq(Pattern::Id, Test::Patternid))
      .joinCond(Eq(Result::Id, Test::Expectid));

  // tuple of Test, DbRule, Pattern, Result
  auto testTuples =
      source.orderBy(Test::Id).queryString(queryFirst.join(" AND "));
  for (const auto& t : testTuples) {
    const auto& test = std::get<Test>(t);
    const auto& rule = std::get<DbRule>(t);
    const auto& pattern = std::get<Pattern>(t);
    const auto& result = std::get<Result>(t); // result can be empty

    auto expectid = (test.expectid.value() == 0) ? matchResult.id.value()
                                                 : test.expectid.value();

    Split queryDetail;
    if (!condEngine.empty())
      queryDetail.push_back(condEngine);
    if (condFailed)
      queryDetail.push_back((TestResult::Resultid != expectid).asString());
    else if (!condExpect.empty())
      queryDetail.push_back((TestResult::Resultid == expectid).asString());

    queryDetail.push_back((TestResult::Testid == test.id.value()).asString());

    JoinedSource<TestResult, Result, Engine> trSource(checker.getDb(), true);
    auto trs = trSource.joinCond(Eq(Result::Id, TestResult::Resultid))
                   .joinCond(Eq(Engine::Id, TestResult::Engineid))
                   .orderBy(TestResult::Id)
                   .queryString(queryDetail.join(" AND "));

    cout << "ID : " << test.id.value() << " (" << rule.name.value() << ", "
         << pattern.name.value() << ")"
         << " expect : "
         << ((result.id.value() > 0) ? result.name.value() : "NULL")
         << " results... ";
    if (trs.empty())
      cout << " (empty)";
    for (const auto& tr : trs)
      cout << std::get<Engine>(tr).name.value() << "=>"
           << std::get<Result>(tr).name.value() << " ";

    cout << endl;
    if (showContent) {
      auto rContent = convertBlob2String(rule.content.value());
      auto pContent = convertBlob2String(pattern.content.value());
      cout << "  rule : " << rContent << endl;
      cout << "  pattern : " << pContent << endl;
    }
  }
}

template <> void CS::processCmd(CS::cmd_show_option& opt)
{
  // show table
  if (!opt[id::table].isValid()) {
    cerr << "command incomplete" << endl;
    return;
  }
  auto& tbl = opt[id::table];
  try {
    if (tbl[id::rule].isValid()) {
      vector<DbRule> dbRules = checker.getAllFromDb<DbRule>();
      for (const auto& r : dbRules) {
        auto content = convertBlob2String(r.content.value());
        cout << "ID : " << r.id.value() << " (" << r.name.value() << ") =>"
             << content << endl;
      }
    }
    if (tbl[id::pattern].isValid()) {
      vector<Pattern> patterns = checker.getAllFromDb<Pattern>();
      for (const auto& p : patterns) {
        auto content = convertBlob2String(p.content.value());
        cout << "ID : " << p.id.value() << " (" << p.name.value() << ") =>"
             << content << endl;
      }
    }
    if (tbl[id::test].isValid()) {
      processTestTable(tbl[id::test]);
    }
  } catch (const Except& e) { // litesql exception
    cerr << e << endl;
  } catch (const std::exception& e) {
    cerr << e.what() << endl;
    return;
  }
}

template <> void CS::processCmd(CS::cmd_clear_option& opt)
{
  if (opt[id::result].isValid()) {
    // clear TestResult table contents
    if (checker.clearResultTable() < 0)
      return;
    cout << "table TestResult cleared" << endl;
  }
}

template <> void CS::processCmd(CS::cmd_exit_option&)
{
  // exit from the shell
  std::cout << "bye\n";
  running = 0;
}

void CS::dispatchCmds(const char* line)
{
  int cmdsC, ret;
  const char** cmds;
  tok_reset(tok); // this is needed because of tab completion
  ret = tok_line(tok, el_line(el), &cmdsC, &cmds, nullptr, nullptr);
  if (ret != 0 || line == nullptr) {
    if (line != nullptr)
      std::cerr << "line tokenizing fail\n";
    return;
  }
  if (!cmdsC) {
    return;
  }

  cmdOpts.reset();
  cCtx.reset(cmdsC, cmds);

  try {
    cmdOpts.parseCmdline(cCtx);
  } catch (std::runtime_error& ex) {
    std::cerr << "error : command parsing fail\n";
    std::cerr << ex.what() << "\n";
    return;
  }

  if (cmdOpts.count(true) == 1) {
    // command match
    cmdOpts.for_each(cmdFunc);
  } else {
    if (cmdOpts.count(true) > 1)
      std::cerr << "error : multiple commands provided\n";
    else
      std::cerr << "error : no matching command found\n";
  }
}

template <typename T> bool CS::convertToInt(const std::string& s, T& t)
{
  static_assert(std::is_integral<T>::value, "integer required");
  char* end;
  long ret = strtol(s.c_str(), &end, 10);
  if (end != nullptr && *end == '\0') { // all characters are valid integral
    t = static_cast<T>(ret);
    return true;
  }
  return false;
}

bool CS::parseCsvLine(const std::string& s, std::vector<std::string>& v)
{
  std::string ifcStr = s;
  std::replace(ifcStr.begin(), ifcStr.end(), ',', ' ');
  std::istringstream is(ifcStr);
  v = std::vector<std::string>((std::istream_iterator<std::string>(is)),
                               std::istream_iterator<std::string>());
  if (!v.empty())
    return true;
  return false;
}
