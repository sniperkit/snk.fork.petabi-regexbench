#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <sstream>
#include <utility>
#include <vector>

#include <boost/program_options.hpp>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <rematch/compile.h>
#include <rematch/execute.h>
#include <rematch/rematch.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../Rule.h"
#include "PcreChecker.h"
#include "litesql_helper.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;

using regexbench::Rule;

namespace po = boost::program_options;

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
using litesql::NotFound;
using litesql::Eq;

const std::string PcreChecker::DB_PREFIX = "database=";
const char* PcreChecker::TMP_TEMPLATE = "tmpdbfilXXXXXX";

PcreChecker::PcreChecker(const std::string& dbFileNam, bool debug)
    : dbFile(dbFileNam)
{
  if (dbFile.empty()) {
    tmpFile = std::make_unique<char[]>(strlen(TMP_TEMPLATE) + 1);
    strncpy(tmpFile.get(), TMP_TEMPLATE, strlen(TMP_TEMPLATE));
    int tmpFd = mkstemp(tmpFile.get());
    if (tmpFd == -1)
      throw std::runtime_error("Could not make temporary db file");
    close(tmpFd);
    dbFile = tmpFile.get();
  }
  dbFile = DB_PREFIX + dbFile;

  pDb = std::make_unique<PcreCheckDb>("sqlite3", dbFile);
  if (debug)
    pDb->verbose = true;
  if (pDb->needsUpgrade())
    pDb->upgrade();
}

PcreChecker::~PcreChecker()
{
  pDb.reset();
  // make sure db is closed before unlinking temp file
  if (tmpFile)
    unlink(tmpFile.get());
}

int PcreChecker::attach(std::string& dbFileNam, bool debug)
{
  if (pDb) {
    dbFileNam = dbFile.substr(dbFile.find(DB_PREFIX) + DB_PREFIX.size());
    return -1;
  }
  if (dbFileNam.empty())
    throw std::runtime_error("Must specify DB file name to attach");

  dbFile = DB_PREFIX + dbFileNam;
  pDb = std::make_unique<PcreCheckDb>("sqlite3", dbFile);
  if (debug)
    pDb->verbose = true;
  if (pDb->needsUpgrade())
    pDb->upgrade();
  return 0;
}

void PcreChecker::detach()
{
  pDb.reset();
  if (tmpFile) {
    unlink(tmpFile.get());
    tmpFile.reset();
  }
}

void PcreChecker::setupDb(const std::string& jsonIn)
{
  if (jsonIn.empty())
    throw std::runtime_error("input json file is not specified");

  std::ifstream jsonFile(jsonIn);

  // Parse json file
  Json::Value root;
  try {
    jsonFile >> root;
  } catch (const std::exception& e) {
    cerr << "json file parse error" << e.what() << endl;
    return;
  }

  try {
    pDb->begin();

    // Parse 'rules'
    json2DbTables<DbRule, JsonFillNameContentDesc<DbRule>>("rules", root);

    // Parse 'grammars'
    json2DbTables<Grammar, JsonFillNameContentDesc<Grammar>>("grammars", root);

    // Parse 'patterns'
    json2DbTables<Pattern, JsonFillNameContentDesc<Pattern>>("patterns", root);

    json2DbTables<Engine, JsonFillNameOnly<Engine>>("engines", root);
    json2DbTables<Result, JsonFillNameOnly<Result>>("results", root);

    // Parse 'tests' (involves tables 'Test', 'TestGrammar', 'TestResult')
    jsonTests2DbTables(root);

    pDb->commit(); // commit changes
  } catch (Except e) {
    cerr << e << endl;
    throw std::runtime_error(
        "litesql exception caught setting up db from json input");
  }
  updateDbMeta();
}

int PcreChecker::clearResultTable()
{
  if (!pDb) {
    cerr << "DB must be attached beforehand" << endl;
    return -1;
  }
  pDb->query("DELETE FROM " + TestResult::table__);
  pDb->commit();
  return 0;
}

void PcreChecker::updateDbMeta()
{
  // scan result ids
  dbMeta.resMatchId =
      select<Result>(*pDb, Result::Name == "match").one().id.value();
  dbMeta.resNomatchId =
      select<Result>(*pDb, Result::Name == "nomatch").one().id.value();
  dbMeta.resErrorId =
      select<Result>(*pDb, Result::Name == "error").one().id.value();

  // engine ids
  dbMeta.engRematchId =
      select<Engine>(*pDb, Engine::Name == "rematch").one().id.value();
  dbMeta.engHyperscanId =
      select<Engine>(*pDb, Engine::Name == "hyperscan").one().id.value();
  dbMeta.engPcreId =
      select<Engine>(*pDb, Engine::Name == "pcre").one().id.value();

  // transform DB rules into regexbench rules (most importantly with id info)
  dbMeta.rules.clear();
  vector<DbRule> dbRules = select<DbRule>(*pDb).orderBy(DbRule::Id).all();
  for (const auto& dbRule : dbRules) {
    auto blob = dbRule.content.value();
    size_t len = blob.length();
    auto temp = std::make_unique<char[]>(len);
    blob.getData(reinterpret_cast<unsigned char*>(temp.get()), len, 0);
    std::string line(temp.get(), len);
    dbMeta.rules.emplace_back(
        regexbench::Rule(line, static_cast<size_t>(dbRule.id.value())));
  }

  dbMeta.needsUpdate = 0;
}

void PcreChecker::checkDb()
{
  if (dbMeta.needsUpdate)
    updateDbMeta();

  try {
    pDb->begin();

    checkRematch();
    checkHyperscan();
    checkPcre();

    pDb->commit(); // commit changes
  } catch (Except e) {
    cerr << e << endl;
    throw std::runtime_error(
        "litesql exception caught updating match result to db");
  }
}

std::array<int, 3> PcreChecker::checkSingle(const std::string& rule,
                                            const std::string& data, bool hex)
{
  std::array<int, 3> results;
  std::string trans;
  const std::string* pData = &data;
  regexbench::Rule singleRule(rule, 1);

  if (hex) {
    trans = convertHexData(data);
    pData = &trans;
  }

  results[0] = checkRematch(&singleRule, pData);
  results[1] = checkHyperscan(&singleRule, pData);
  results[2] = checkPcre(&singleRule, pData);

  return results;
}

void PcreChecker::writeJson(const std::string& jsonOut)
{
  if (jsonOut.empty())
    throw std::runtime_error("input json file is not specified");
  if (!pDb)
    throw std::runtime_error("DB must have been attached for writing json");

  std::ofstream jsonFile(jsonOut);
  Json::Value root;

  // rules
  dbTables2Json<DbRule, JsonFillNameContentDesc<DbRule>>("rules", root);

  // patterns
  dbTables2Json<Pattern, JsonFillNameContentDesc<Pattern>>("patterns", root);

  // grammars
  dbTables2Json<Grammar, JsonFillNameContentDesc<Grammar>>("grammars", root);

  // engines & results
  dbTables2Json<Engine, JsonFillNameOnly<Engine>>("engines", root);
  dbTables2Json<Result, JsonFillNameOnly<Result>>("results", root);

  // tests : these are tricky parts because we should mix rule, pattern, grammar
  // and result altogether
  dbTables2JsonTests(root); // TBD

  // time to write to a file
  Json::StreamWriterBuilder wbuilder;
  jsonFile << Json::writeString(wbuilder, root);
  jsonFile << endl;
}

void PcreChecker::dbTables2JsonTests(Json::Value& root) const
{
  JoinedSource<Test, DbRule, Pattern, Result> source(*pDb,
                                                     true); // use left join
  // result table can be empty (because expectid can be 0)
  source.joinCond(Eq(DbRule::Id, Test::Ruleid))
      .joinCond(Eq(Pattern::Id, Test::Patternid))
      .joinCond(Eq(Result::Id, Test::Expectid));

  auto tuples = source.orderBy(Test::Id).query();
  for (const auto& t : tuples) {
    Json::Value entry;
    const auto& test = std::get<Test>(t);
    const auto& rule = std::get<DbRule>(t);
    const auto& pattern = std::get<Pattern>(t);
    const auto& result = std::get<Result>(t); // result can be empty

    entry["rule"] = rule.name.value();
    entry["pattern"] = pattern.name.value();
    if (result.id.value() > 0)
      entry["expect"] = result.name.value();

    // now check TestGrammar
    JoinedSource<TestGrammar, Grammar> grSource(*pDb, true);
    auto grs = grSource.joinCond(Eq(Grammar::Id, TestGrammar::Grammarid))
                   .orderBy(Grammar::Id)
                   .query(TestGrammar::Testid == test.id.value());
    for (const auto& gr : grs)
      entry["grammars"].append(std::get<Grammar>(gr).name.value());

    // now check TestResult
    JoinedSource<TestResult, Result, Engine> trSource(*pDb, true);
    auto trs = trSource.joinCond(Eq(Result::Id, TestResult::Resultid))
                   .joinCond(Eq(Engine::Id, TestResult::Engineid))
                   .orderBy(TestResult::Id)
                   .query(TestResult::Testid == test.id.value());
    for (const auto& tr : trs)
      entry["result"][std::get<Engine>(tr).name.value()] =
          std::get<Result>(tr).name.value();

    root["tests"].append(entry);
  }
}

void PcreChecker::jsonTests2DbTables(const Json::Value& root)
{
  const auto& tests = root["tests"];
  if (tests.empty())
    return;
  if (!tests.isArray()) {
    throw std::runtime_error("tests should be array type");
  }

  std::map<string, int> engineMap;
  std::map<string, int> resultMap;

  std::vector<Engine> engineSels = select<Engine>(*pDb).all();
  for (const auto& e : engineSels) {
    engineMap[e.name.value()] = e.id.value();
  }
  std::vector<Result> resultSels = select<Result>(*pDb).all();
  for (const auto& r : resultSels) {
    resultMap[r.name.value()] = r.id.value();
  }

  // rule => DbRule name
  // pattern => Pattern name
  // grammars => array of Grammar names
  // result => json object of result for each engine
  for (const auto& test : tests) {
    if (test["rule"].empty() || !test["rule"].isString())
      throw std::runtime_error("test rule name must be specfied (as string)");
    if (test["pattern"].empty() || !test["pattern"].isString())
      throw std::runtime_error(
          "test pattern name must be specfied (as string)");
    const auto& rulename = test["rule"].asString();
    const auto& patternname = test["pattern"].asString();

    // find ids of rule, pattern, grammar
    int rule_id;
    int pattern_id;
    try {
      const auto& rule_db =
          select<DbRule>(*pDb, DbRule::Name == rulename).one();
      rule_id = rule_db.id.value();
      const auto& pattern_db =
          select<Pattern>(*pDb, Pattern::Name == patternname).one();
      pattern_id = pattern_db.id.value();
    } catch (NotFound e) {
      cerr << "rule(" << rulename << ") or pattern(" << patternname
           << ") not found (" << e << ") (skipping this)" << endl;
      continue;
    }
    // find expect id : this is actually a result id
    int expect_id = 0;
    if (!test["expect"].empty() && test["expect"].isString()) {
      if (resultMap.count(test["expect"].asString()))
        expect_id = resultMap.at(test["expect"].asString());
    }

    // now rule_id, pattern_id, expect_id are valid
    // find out Test table id if any or create one
    int test_id;
    try {
      const auto& test_db =
          select<Test>(*pDb,
                       Test::Ruleid == rule_id && Test::Patternid == pattern_id)
              .one();
      test_id = test_db.id.value();
    } catch (NotFound) {
      Test test_db(*pDb);
      test_db.ruleid = rule_id;
      test_db.patternid = pattern_id;
      test_db.expectid = expect_id;
      test_db.update();
      test_id = test_db.id.value();
    }

    std::vector<int> grammar_ids;
    if (!test["grammars"].empty()) {
      const auto& grammars = test["grammars"];
      for (const auto& gr : grammars) {
        if (!gr.isString())
          continue; // TODO
        try {
          const auto& gr_db =
              select<Grammar>(*pDb, Grammar::Name == gr.asString()).one();
          grammar_ids.push_back(gr_db.id.value());
        } catch (NotFound) {
          // just register this grammar on the fly (w/o description)
          Grammar new_gr(*pDb);
          new_gr.name = gr.asString();
          new_gr.update();
          grammar_ids.push_back(new_gr.id.value());
        }
      }
    }

    for (auto gid : grammar_ids) {
      try {
        select<TestGrammar>(*pDb,
                            TestGrammar::Testid == test_id &&
                                TestGrammar::Grammarid == gid)
            .one();
      } catch (NotFound) {
        TestGrammar tg(*pDb);
        tg.testid = test_id;
        tg.grammarid = gid;
        tg.update();
      }
    }

    std::map<string, string> verdictMap;
    if (!test["result"].empty() && test["result"].isObject()) {
      const auto& result = test["result"];
      for (const auto& engine : result.getMemberNames()) {
        if (engineMap.find(engine) != engineMap.end()) { // engine names
          const auto& verdict = result[engine].asString();
          if (result[engine].isString() &&
              resultMap.find(verdict) != resultMap.end()) {
            verdictMap[engine] = verdict;
          } else {
            cerr << "result for engine " << engine << " set incorrectly"
                 << endl;
          }
        } else {
          cerr << "unknown engine " << engine << " for result" << endl;
        }
      }
    }

    for (auto e2V : verdictMap) {
      try {
        auto resEntry = *(
            select<TestResult>(*pDb,
                               TestResult::Testid == test_id &&
                                   TestResult::Engineid == engineMap[e2V.first])
                .cursor());

        resEntry.resultid = resultMap[e2V.second];
        resEntry.update();
      } catch (NotFound) {
        TestResult resEntry(*pDb);
        resEntry.testid = test_id;
        resEntry.engineid = engineMap[e2V.first];
        resEntry.resultid = resultMap[e2V.second];
        resEntry.update();
      }
    }
  }
}

static int onMatch(unsigned id, unsigned long long from, unsigned long long to,
                   unsigned flags, void* ctx)
{
  auto res = static_cast<rematchResult*>(ctx);
  res->pushId(id);
  return 0; // continue till there's no more match
}

int PcreChecker::checkRematch(const regexbench::Rule* singleRule,
                              const std::string* data)
{
  int result = 0;
  int engineId = dbMeta.engRematchId;

  if (singleRule && !data)
    throw std::runtime_error(
        "If rule was given data should also be given in single check mode");

  rematch2_t* matcher;
  rematch_scratch_t* scratch;
  rematch_match_context_t* context;
  vector<const char*> rematchExps;
  vector<unsigned> rematchMods;
  vector<unsigned> rematchIds;
  if (singleRule) {
    const auto& rule = *singleRule;
    rematchExps.push_back(rule.getRegexp().data());
    rematchIds.push_back(static_cast<unsigned>(rule.getID()));
    uint32_t opt = 0;
    if (rule.isSet(regexbench::MOD_CASELESS))
      opt |= REMATCH_MOD_CASELESS;
    if (rule.isSet(regexbench::MOD_MULTILINE))
      opt |= REMATCH_MOD_MULTILINE;
    if (rule.isSet(regexbench::MOD_DOTALL))
      opt |= REMATCH_MOD_DOTALL;
    rematchMods.push_back(opt);
  } else {
    for (const auto& rule : dbMeta.rules) {
      rematchExps.push_back(rule.getRegexp().data());
      rematchIds.push_back(static_cast<unsigned>(rule.getID()));
      uint32_t opt = 0;
      if (rule.isSet(regexbench::MOD_CASELESS))
        opt |= REMATCH_MOD_CASELESS;
      if (rule.isSet(regexbench::MOD_MULTILINE))
        opt |= REMATCH_MOD_MULTILINE;
      if (rule.isSet(regexbench::MOD_DOTALL))
        opt |= REMATCH_MOD_DOTALL;
      rematchMods.push_back(opt);
    }
  }
  matcher = rematch2_compile_with_shortcuts(
      rematchIds.data(), rematchExps.data(), rematchMods.data(),
      rematchIds.size(), false /* reduce */
      ,
      false);
  if (!matcher)
    throw std::runtime_error("Could not build REmatch2 matcher.");
  scratch = rematch_alloc_scratch(matcher);
  context = rematch2ContextInit(matcher);
  if (context == nullptr)
    throw std::runtime_error("Could not initialize context.");

  rematchResult matchRes;
  // prepare data (only need the data specified in Test table)
  int lastPid = -1;
  if (singleRule) {   // single test mode
    matchRes.clear(); // must be done to get right result
    int ret = rematch_scan_block(matcher, data->data(), data->size(), context,
                                 scratch, onMatch, &matchRes);
    if (ret == MREG_FAILURE)
      cerr << "rematch failed during matching for a packet" << endl;
    result = matchRes.isMatched() ? 1 : 0;
  } else {
    vector<Test> tests = select<Test>(*pDb).orderBy(Test::Patternid).all();
    for (const auto& t : tests) {
      if (t.patternid.value() == lastPid)
        continue;
      lastPid = t.patternid.value();
      // we can get excption below
      // (which should not happen with a db correctly set up)
      const auto& pattern = select<Pattern>(*pDb, Pattern::Id == lastPid).one();
      auto blob = pattern.content.value();
      size_t len = blob.length();
      auto temp = std::make_unique<char[]>(len);
      blob.getData(reinterpret_cast<unsigned char*>(temp.get()), len, 0);

      // for debugging
      // cout << "pattern " << lastPid << " content : " << string(temp.get(),
      // len)
      //     << endl;

      // set up Rule-id to (Test-id, result) mapping to be used for TestResult
      // update
      std::map<int, std::pair<int, bool>> rule2TestMap;
      auto curTest = select<Test>(*pDb, Test::Patternid == lastPid).cursor();
      for (; curTest.rowsLeft(); curTest++) {
        rule2TestMap[(*curTest).ruleid.value()] =
            std::make_pair((*curTest).id.value(), false);
      }

      // do match
      matchRes.clear(); // must be done to get right result
      int ret = rematch_scan_block(matcher, temp.get(), len, context, scratch,
                                   onMatch, &matchRes);
      if (ret == MREG_FAILURE)
        cerr << "rematch failed during matching for a packet" << endl;
      if (matchRes.isMatched()) {
        // for debugging
        // cout << "pattern " << lastPid;
        // cout << " matched rules :" << endl;
        for (auto id : matchRes) {
          // for debugging
          // cout << " " << id;
          if (rule2TestMap.count(static_cast<int>(id)) > 0)
            rule2TestMap[static_cast<int>(id)].second = true;
        }
      } else {
        cout << "pattern " << lastPid << " has no match" << endl;
      }
      // cout << endl;
      rematch2ContextClear(context, true);

      // for debugging
      // cout << "Matched rule and test id for pattern id " << lastPid << endl;
      // for (const auto& p : rule2TestMap) {
      //  cout << " rule id " << p.first << " test id " << p.second.first
      //       << " matched? " << p.second.second << endl;
      //}
      for (const auto& p : rule2TestMap) {
        try {
          auto cur =
              *(select<TestResult>(*pDb,
                                   TestResult::Testid == p.second.first &&
                                       TestResult::Engineid == engineId)
                    .cursor());
          cur.resultid =
              (p.second.second ? dbMeta.resMatchId : dbMeta.resNomatchId);
          cur.update();
          // for debugging
          // cout << " TestResult id " << cur.id << " updated to  result "
          //     << cur.resultid << "(" << p.second.second << ")" << endl;
        } catch (NotFound) {
          TestResult res(*pDb);
          res.testid = p.second.first;
          res.engineid = engineId;
          res.resultid =
              (p.second.second ? dbMeta.resMatchId : dbMeta.resNomatchId);
          res.update();
        }
      }
    } // for loop for Test table entries
  }

  // clean-up of REmatch related objects
  rematch_free_scratch(scratch);
  rematch2ContextFree(context);
  rematch2Free(matcher);

  return result;
}

static int hsOnMatch(unsigned int, unsigned long long, unsigned long long,
                     unsigned int, void* ctx)
{
  size_t& nmatches = *static_cast<size_t*>(ctx);
  nmatches++;
  return 0;
}

int PcreChecker::checkHyperscan(const regexbench::Rule* singleRule,
                                const std::string* data)
{
  if (singleRule && !data)
    throw std::runtime_error(
        "If rule was given data should also be given in single check mode");

  int result = 0;
  int engineId = dbMeta.engHyperscanId;

  hs_database_t* hsDb = nullptr;
  hs_scratch_t* hsScratch = nullptr;
  // hs_platform_info_t hsPlatform;
  hs_compile_error_t* hsErr = nullptr;

  if (singleRule) {
    const auto& rule = *singleRule;
    unsigned flag = HS_FLAG_ALLOWEMPTY;
    if (rule.isSet(regexbench::MOD_CASELESS))
      flag |= HS_FLAG_CASELESS;
    if (rule.isSet(regexbench::MOD_MULTILINE))
      flag |= HS_FLAG_MULTILINE;
    if (rule.isSet(regexbench::MOD_DOTALL))
      flag |= HS_FLAG_DOTALL;

    auto resCompile = hs_compile(rule.getRegexp().data(), flag, HS_MODE_BLOCK,
                                 nullptr, &hsDb, &hsErr);
    if (resCompile == HS_SUCCESS) {
      auto resAlloc = hs_alloc_scratch(hsDb, &hsScratch);
      if (resAlloc != HS_SUCCESS) {
        hs_free_database(hsDb);
        throw std::bad_alloc();
      }
    } else {
      hs_free_compile_error(hsErr);
      return -1;
    }

    size_t nmatches = 0;
    hs_scan(hsDb, data->data(), static_cast<unsigned>(data->size()), 0,
            hsScratch, hsOnMatch, &nmatches);
    result = (nmatches > 0) ? 1 : 0;

    hs_free_scratch(hsScratch);
    hs_free_database(hsDb);
    return result;
  }

  auto cur = select<Test>(*pDb).orderBy(Test::Ruleid).cursor();
  if (!cur.rowsLeft()) // nothing to do
    return result;

  // map of Test-id to Result-id
  std::map<int, int> test2ResMap;

  // Entering into this loop, please make sure that
  // rules and cur are all sorted w.r.t rule id
  // (only, cur can have multiple occurrences of rule id's)
  // and also rules be super set of the iteration cur points to
  // in terms of containing rule id's.
  // Below outer and inner loop is assuming the above constraints
  // to prevent multiple rule compile for a same rule
  for (const auto& rule : dbMeta.rules) {
    if (!cur.rowsLeft())
      break;
    if (rule.getID() != static_cast<size_t>((*cur).ruleid.value()))
      continue;

    unsigned flag = HS_FLAG_ALLOWEMPTY;
    if (rule.isSet(regexbench::MOD_CASELESS))
      flag |= HS_FLAG_CASELESS;
    if (rule.isSet(regexbench::MOD_MULTILINE))
      flag |= HS_FLAG_MULTILINE;
    if (rule.isSet(regexbench::MOD_DOTALL))
      flag |= HS_FLAG_DOTALL;

    hsDb = nullptr;
    hsScratch = nullptr;
    hsErr = nullptr;
    auto resCompile = hs_compile(rule.getRegexp().data(), flag, HS_MODE_BLOCK,
                                 nullptr, &hsDb, &hsErr);
    if (resCompile == HS_SUCCESS) {
      auto resAlloc = hs_alloc_scratch(hsDb, &hsScratch);
      if (resAlloc != HS_SUCCESS) {
        hs_free_database(hsDb);
        throw std::bad_alloc();
      }
    } else
      hs_free_compile_error(hsErr);

    for (; cur.rowsLeft() &&
           rule.getID() == static_cast<size_t>((*cur).ruleid.value());
         cur++) {

      if (resCompile != HS_SUCCESS) {
        test2ResMap[(*cur).id.value()] = dbMeta.resErrorId;
        continue;
      }

      const auto& pattern =
          select<Pattern>(*pDb, Pattern::Id == (*cur).patternid).one();
      auto blob = pattern.content.value();
      size_t len = blob.length();
      auto temp = std::make_unique<char[]>(len);
      blob.getData(reinterpret_cast<unsigned char*>(temp.get()), len, 0);

      size_t nmatches = 0;
      hs_scan(hsDb, temp.get(), static_cast<unsigned>(len), 0, hsScratch,
              hsOnMatch, &nmatches);
      test2ResMap[(*cur).id.value()] =
          (nmatches > 0) ? dbMeta.resMatchId : dbMeta.resNomatchId;
    }

    hs_free_scratch(hsScratch);
    hs_free_database(hsDb);
  }

  // cout << "Hyper scan result" << endl << endl;
  for (const auto& p : test2ResMap) {
    try {
      auto curT = *(select<TestResult>(*pDb,
                                       TestResult::Testid == p.first &&
                                           TestResult::Engineid == engineId)
                        .cursor());
      curT.resultid = p.second;
      curT.update();
    } catch (NotFound) {
      TestResult res(*pDb);
      res.testid = p.first;
      res.engineid = engineId;
      res.resultid = p.second;
      res.update();
    }
    // for debugging
    // const auto& test = select<Test>(*pDb, Test::Id == p.first).one();
    // cout << "test " << test.id.value() << " (rule id " << test.ruleid.value()
    //     << ", pattern id " << test.patternid.value()
    //     << ") => result : " << p.second << endl;
  }

  return result;
}

int PcreChecker::checkPcre(const regexbench::Rule* singleRule,
                           const std::string* data)
{
  if (singleRule && !data)
    throw std::runtime_error(
        "If rule was given data should also be given in single check mode");

  int result = 0;
  int engineId = dbMeta.engPcreId;

  if (singleRule) {
    const auto& rule = *singleRule;
    PCRE2_SIZE erroffset = 0;
    int errcode = 0;
    pcre2_code* re =
        pcre2_compile(reinterpret_cast<PCRE2_SPTR>(rule.getRegexp().data()),
                      PCRE2_ZERO_TERMINATED, rule.getPCRE2Options(), &errcode,
                      &erroffset, nullptr);
    pcre2_match_data* mdata = nullptr;
    if (re != nullptr) {
      mdata = pcre2_match_data_create_from_pattern(re, nullptr);
    } else
      return -1;

    int rc = pcre2_match(
        re, reinterpret_cast<PCRE2_SPTR>(data->data()), data->size(), 0,
        PCRE2_NOTEMPTY_ATSTART | PCRE2_NOTEMPTY, mdata, nullptr);

    result = (rc >= 0) ? 1 : 0;

    pcre2_code_free(re);
    pcre2_match_data_free(mdata);
    return result;
  }

  auto cur = select<Test>(*pDb).orderBy(Test::Ruleid).cursor();
  if (!cur.rowsLeft()) // nothing to do
    return result;

  // map of Test-id to Result-id
  std::map<int, int> test2ResMap;

  // Entering into this loop, please make sure that
  // rules and cur are all sorted w.r.t rule id
  // (only, cur can have multiple occurrences of rule id's)
  // and also rules be super set of the iteration cur points to
  // in terms of containing rule id's.
  // Below outer and inner loop is assuming the above constraints
  // to prevent multiple rule compile for a same rule
  for (const auto& rule : dbMeta.rules) {
    if (!cur.rowsLeft())
      break;
    if (rule.getID() != static_cast<size_t>((*cur).ruleid.value()))
      continue;

    PCRE2_SIZE erroffset = 0;
    int errcode = 0;
    pcre2_code* re =
        pcre2_compile(reinterpret_cast<PCRE2_SPTR>(rule.getRegexp().data()),
                      PCRE2_ZERO_TERMINATED, rule.getPCRE2Options(), &errcode,
                      &erroffset, nullptr);
    pcre2_match_data* mdata = nullptr;
    if (re != nullptr) {
      mdata = pcre2_match_data_create_from_pattern(re, nullptr);
    }

    for (; cur.rowsLeft() &&
           rule.getID() == static_cast<size_t>((*cur).ruleid.value());
         cur++) {

      if (re == nullptr) {
        test2ResMap[(*cur).id.value()] = dbMeta.resErrorId;
        continue;
      }

      const auto& pattern =
          select<Pattern>(*pDb, Pattern::Id == (*cur).patternid).one();
      auto ctype = pattern.ctype.value();
      auto blob = pattern.content.value();
      size_t len = blob.length();
      auto temp = std::make_unique<char[]>(len);
      blob.getData(reinterpret_cast<unsigned char*>(temp.get()), len, 0);

      int rc =
          pcre2_match(re, reinterpret_cast<PCRE2_SPTR>(temp.get()), len, 0,
                      PCRE2_NOTEMPTY_ATSTART | PCRE2_NOTEMPTY, mdata, nullptr);

      test2ResMap[(*cur).id.value()] =
          (rc >= 0) ? dbMeta.resMatchId : dbMeta.resNomatchId;
    }

    pcre2_code_free(re);
    pcre2_match_data_free(mdata);
  }

  // cout << "PCRE match result" << endl << endl;
  for (const auto& p : test2ResMap) {
    try {
      auto curT = *(select<TestResult>(*pDb,
                                       TestResult::Testid == p.first &&
                                           TestResult::Engineid == engineId)
                        .cursor());
      curT.resultid = p.second;
      curT.update();
    } catch (NotFound) {
      TestResult res(*pDb);
      res.testid = p.first;
      res.engineid = engineId;
      res.resultid = p.second;
      res.update();
    }
    // for debugging
    // const auto& test = select<Test>(*pDb, Test::Id == p.first).one();
    // cout << "test " << test.id.value() << " (rule id " << test.ruleid.value()
    //     << ", pattern id " << test.patternid.value()
    //     << ") => result : " << p.second << endl;
  }
  return result;
}

std::string convertHexData(const std::string& data)
{
  size_t pos = 0;
  std::string tmpStr, convCh, resultStr = data;

  while ((pos = resultStr.find("\\x", pos)) != std::string::npos) {
    tmpStr = resultStr.substr(pos + 2, 2);
    if (hexToCh(tmpStr, convCh)) {
      resultStr.erase(pos, 4);
      resultStr.insert(pos, convCh);
    } else {
      pos += 2;
      continue;
    }
  }
  return resultStr;
}

std::string convertBlob2String(const litesql::Blob& blobConst)
{
  auto blob = blobConst; // ugly but
                         // getData is not declared const
  size_t len = blob.length();
  auto temp = std::make_unique<char[]>(len);
  blob.getData(reinterpret_cast<unsigned char*>(temp.get()), len, 0);
  return std::string(temp.get(), len);
}

bool hexToCh(std::string& hex, std::string& conv)
{
  for (auto d : hex) {
    if (!isxdigit(d)) {
      return false;
    }
  }
  try {
    char data = static_cast<char>(std::stoi(hex, 0, 16));
    conv = std::string(1, data);
  } catch (const std::exception& e) {
    cerr << "hex convert fail " << e.what() << endl;
    return false;
  }
  return true;
}
