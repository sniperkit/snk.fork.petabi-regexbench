#ifndef PCRE_CHECKER_H
#define PCRE_CHECKER_H

#include <array>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <json/json.h>
#include <litesql.hpp>

#include "../Rule.h"
#include "pcrecheckdb.hpp"

std::string convertHexData(const std::string& data);
std::string convertBlob2String(const litesql::Blob& blob);
bool hexToCh(std::string& hex, std::string& conv);

class PcreChecker {
public:
  PcreChecker(const std::string& dbFile = "", bool debug = false);
  ~PcreChecker();

  int attach(std::string& dbFile, bool debug = false);
  void detach();

  void setupDb(const std::string& jsonIn);
  int clearResultTable();
  void checkDb();
  std::array<int, 3> checkSingle(const std::string& rule,
                                 const std::string& data, bool hex = false);
  void writeJson(const std::string& jsonOut);
  void writePcap(const std::string& pcapOut);

  const pcre_check::PcreCheckDb& getDb() const { return *pDb; }
  template <typename T> std::vector<T> getAllFromDb() const;

private:
  template <typename T, typename F>
  void dbTables2Json(const std::string& member, Json::Value& root) const;
  void dbTables2JsonTests(Json::Value& root) const;
  template <typename T, typename F>
  void json2DbTables(const std::string& member, const Json::Value& root);
  void jsonTests2DbTables(const Json::Value&);

  int checkRematch(const regexbench::Rule* rule = nullptr,
                   const std::string* data = nullptr);
  int checkHyperscan(const regexbench::Rule* rule = nullptr,
                     const std::string* data = nullptr);
  int checkPcre(const regexbench::Rule* rule = nullptr,
                const std::string* data = nullptr);

  void updateDbMeta();

  std::unique_ptr<pcre_check::PcreCheckDb> pDb;
  std::string dbFile;

  // auxiliary data
  static const std::string DB_PREFIX;
  static const char* TMP_TEMPLATE;
  std::unique_ptr<char[]> tmpFile;
  struct DbMeta {
    int needsUpdate = 1;
    int resMatchId;
    int resNomatchId;
    int resErrorId;
    int engRematchId;
    int engHyperscanId;
    int engPcreId;
    std::vector<regexbench::Rule> rules;
  };
  DbMeta dbMeta;
};

class rematchResult {
public:
  rematchResult(size_t res = 32)
  {
    // reserving appropriate size could improve initial performance
    ids.reserve(res);
  }
  void clear() { ids.clear(); }
  void pushId(unsigned id) { ids.push_back(id); }

  bool isMatched() { return !ids.empty(); }

  // just a wrapper over std::vector<unsigned>::iterator
  class iterator : public std::iterator<std::input_iterator_tag, unsigned> {
  public:
    iterator(std::vector<unsigned>::iterator i) : it(i) {}
    iterator& operator++()
    {
      ++it;
      return *this;
    }
    iterator operator++(int)
    {
      iterator retval = *this;
      ++(*this);
      return retval;
    }
    bool operator==(iterator other) const { return it == other.it; }
    bool operator!=(iterator other) const { return !(*this == other); }
    reference operator*() const { return *it; }

  private:
    std::vector<unsigned>::iterator it;
  };

  iterator begin() { return iterator(ids.begin()); }
  iterator end() { return iterator(ids.end()); }

private:
  std::vector<unsigned> ids;
};

template <typename T> std::vector<T> PcreChecker::getAllFromDb() const
{
  std::vector<T> items = litesql::select<T>(*pDb).orderBy(T::Id).all();
  return items;
}

template <typename T, typename F>
void PcreChecker::dbTables2Json(const std::string& member,
                                Json::Value& root) const
{
  std::vector<T> items = getAllFromDb<T>();

  for (const auto& item : items) {
    Json::Value jItem;
    F()(jItem, item);
    root[member].append(jItem);
  }
}

template <typename T, typename F>
void PcreChecker::json2DbTables(const std::string& member,
                                const Json::Value& root)
{
  const auto& jsonArr = root[member];
  if (jsonArr.empty())
    return;
  if (!jsonArr.isArray())
    throw std::runtime_error(std::string(member + "should be array type"));

  for (const auto& jItem : jsonArr) {
    T dbRow(*pDb);
    if (F()(dbRow, jItem, *pDb, member))
      dbRow.update();
  }
}

template <typename T> struct JsonFillNameOnly {
  // translate db to json
  void operator()(Json::Value& jItem, const T& dbRow)
  {
    jItem = dbRow.name.value();
  }

  // translate json to db
  int operator()(T& dbRow, const Json::Value& jItem,
                 pcre_check::PcreCheckDb& db, const std::string& member)
  {
    if (jItem.empty() || !jItem.isString())
      throw std::runtime_error(
          std::string(member + " name must be specfied (as string)"));
    const auto& name = jItem.asString();

    try {
      litesql::select<T>(db, T::Name == name).one();
      std::cerr << member << " entry with name " << name
                << " already exists in DB (skipping this)" << std::endl;
      return 0;
    } catch (litesql::NotFound) {
      dbRow.name = name;
    }
    return 1;
  }
};

template <typename T> struct JsonFillNameContentDesc {
  // this structure provides () operators that processes
  // name, content, desc items for either direction : db <-> json
  // these () operators are able to detect whether the DB type of interest
  // supports 'content' member or not and process data accordingly

  // translate db to json
  void operator()(Json::Value& jItem, const T& dbRow)
  {
    jItem["name"] = dbRow.name.value();
    dbContent2Json(jItem, dbRow, 0);
    if (!dbRow.desc.value().empty())
      jItem["desc"] = dbRow.desc.value();
  }

  // translate json to db
  int operator()(T& dbRow, const Json::Value& jItem,
                 pcre_check::PcreCheckDb& db, const std::string& member)
  {
    if (jItem["name"].empty() || !jItem["name"].isString())
      throw std::runtime_error(
          std::string(member + " name must be specfied (as string)"));
    const auto& name = jItem["name"].asString();

    try {
      litesql::select<T>(db, T::Name == name).one();
      std::cerr << member << " entry with name " << name
                << " already exists in DB (skipping this)" << std::endl;
      return 0;
    } catch (litesql::NotFound) {
      dbRow.name = name;
    }
    memberName = member;
    jsonContent2Db(dbRow, jItem, 0);
    if (!jItem["desc"].empty())
      dbRow.desc = jItem["desc"].asString();
    return 1;
  }

private:
  // two versions of dbContent2Json funcs to make use of SFINAE.
  // the first version will be taken when type U has 'Content' static member
  // which litesql code generator will automatically make when the table
  // has a member named 'content'.
  // The return values of these funcs are not meaningful; they are only there
  // to make SFINAE work.
  template <typename U>
  decltype(U::Content) dbContent2Json(Json::Value& jItem, const U& dbRow, int)
  {
    jItem["content"] = convertBlob2String(dbRow.content.value());
    return U::Content;
  }
  template <typename U>
  int dbContent2Json(Json::Value& jItem, const U& dbRow, long)
  {
    // called when there's no content member with U
    return 0;
  }

  // two versions of jsonContent2Db funcs to make use of SFINAE.
  // the first version will be taken when type U has 'Content' static member
  // which litesql code generator will automatically make when the table
  // has a member named 'content'.
  // The return values of these funcs are not meaningful; they are only there
  // to make SFINAE work.
  template <typename U>
  decltype(U::Content) jsonContent2Db(U& dbRow, const Json::Value& jItem, int)
  {
    if (jItem["content"].empty() || !jItem["content"].isString())
      throw std::runtime_error(
          std::string(memberName + " content must be specfied (as string)"));
    const auto& content = jItem["content"].asString();
    jsonContentWithCtype2Db(dbRow, jItem, content, 0);
    return U::Content;
  }
  template <typename U>
  int jsonContent2Db(U& dbRow, const Json::Value& jItem, long)
  {
    // called when there's no content member with U
    return 0;
  }

  // two versions of jsonContentWithCtype2Db funcs to make use of SFINAE.
  // the first version will be taken when type U has 'Ctype' static member
  // which litesql code generator will automatically make when the table
  // has a member named 'ctype'.
  // The return values of these funcs are not meaningful; they are only there
  // to make SFINAE work.
  template <typename U>
  decltype(U::Ctype) jsonContentWithCtype2Db(U& dbRow, const Json::Value& jItem,
                                             const std::string& content, int)
  {
    if (!jItem["ctype"].empty() &&
        (jItem["ctype"] != "hex" && jItem["ctype"] != "str"))
      throw std::runtime_error(
          std::string(memberName +
                      " content type must be specified properly (hex or str)"));
    if (jItem["ctype"].empty() || jItem["ctype"].asString() == "str") {
      dbRow.ctype = "str";
      dbRow.content = litesql::Blob(content.data(), content.size());
    } else {
      dbRow.ctype = jItem["ctype"].asString(); // "hex"
      std::string tmp = convertHexData(content.data());
      dbRow.content = litesql::Blob(tmp.data(), tmp.size());
    }
    return U::Ctype;
  }
  template <typename U>
  int jsonContentWithCtype2Db(U& dbRow, const Json::Value& jItem,
                              const std::string& content, long)
  {
    dbRow.content = litesql::Blob(content.data(), content.size());
    return 0;
  }

  std::string memberName;
};

#endif
