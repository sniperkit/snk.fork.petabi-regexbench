#include <iterator>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <boost/fusion/algorithm/iteration/for_each.hpp>
#include <boost/fusion/container/map.hpp>
#include <boost/fusion/container/map/map_fwd.hpp>
#include <boost/fusion/include/at_key.hpp>
#include <boost/fusion/include/has_key.hpp>
#include <boost/fusion/include/map.hpp>
#include <boost/fusion/include/map_fwd.hpp>
#include <boost/fusion/sequence/intrinsic/at_key.hpp>
#include <boost/fusion/sequence/intrinsic/has_key.hpp>

#include <litesql.hpp>

class JoinedQuery {
  bool _distinct;
  int _limit, _offset;
  litesql::Split _results;
  litesql::Split _sources;
  litesql::Split _ljoins;
  std::string _where;
  litesql::Split _groupBy;
  std::string _having;
  litesql::Split _orderBy;

public:
  JoinedQuery() : _distinct(false), _limit(0), _offset(0), _where("True") {}
  JoinedQuery& distinct(bool d)
  {
    _distinct = d;
    return *this;
  }
  JoinedQuery& limit(int value)
  {
    _limit = value;
    return *this;
  }

  JoinedQuery& offset(int value)
  {
    _offset = value;
    return *this;
  }

  JoinedQuery& result(std::string r)
  {
    _results.push_back(r);
    return *this;
  }

  JoinedQuery& clearResults()
  {
    _results.clear();
    return *this;
  }

  JoinedQuery& source(std::string s, std::string alias = "")
  {
    if (!alias.empty())
      s += " AS " + alias;
    _sources.push_back(s);
    return *this;
  }

  JoinedQuery& ljoin(std::string s)
  {
    _ljoins.push_back(s);
    return *this;
  }

  JoinedQuery& where(const litesql::Expr& w)
  {
    _where = (litesql::RawExpr(_where) && w).asString();
    return *this;
  }

  JoinedQuery& where(std::string w)
  {
    _where = (litesql::RawExpr(_where) && litesql::RawExpr(w)).asString();
    return *this;
  }

  JoinedQuery& groupBy(std::string gb)
  {
    _groupBy.push_back(gb);
    return *this;
  }

  JoinedQuery& having(const litesql::Expr& h)
  {
    _having = h.asString();
    return *this;
  }

  JoinedQuery& having(std::string h)
  {
    _having = h;
    return *this;
  }

  JoinedQuery& orderBy(std::string ob, bool ascending = true)
  {
    std::string value = ob;
    if (!ascending)
      value += " DESC";
    _orderBy.push_back(value);
    return *this;
  }

  operator std::string() const
  {
    std::string res = "SELECT ";
    if (_distinct)
      res += "DISTINCT ";
    res += _results.join(",");
    res += " FROM ";
    res += _sources.join(",");
    for (const auto& lj : _ljoins)
      res += " LEFT JOIN " + lj;
    if (_where != "True")
      res += " WHERE " + _where;
    if (_groupBy.size() > 0)
      res += " GROUP BY " + _groupBy.join(",");
    if (!_having.empty())
      res += " HAVING " + _having;
    if (_orderBy.size() > 0)
      res += " ORDER BY " + _orderBy.join(",");
    if (_limit)
      res += " LIMIT " + litesql::toString(_limit);
    if (_offset)
      res += " OFFSET " + litesql::toString(_offset);
    return res;
  }

  std::string asString() const { return this->operator std::string(); }
};

template <typename... T> class JoinedSource {
public:
  typedef boost::fusion::map<
      boost::fusion::pair<T, std::pair<size_t, size_t>>...>
      map_type;
  typedef std::tuple<T...> tuple_type;

  JoinedSource(const litesql::Database& db_, bool left = false)
      : db(db_), leftjoin(left),
        typeMap(boost::fusion::make_pair<T>(std::make_pair(0, 0))...)
  {
    setupInternal();
  }

  template <typename... E> JoinedSource& joinCond(E&&... e)
  {
    if (!leftjoin)
      return *this;

    // if joinConds are not empty we just add cond on tail of it
    // but we ignore joinCond call attempt when joinConds size has
    // already exceeded table size - 1
    if (joinConds.size() >= tables.size())
      return *this;

    int dummy[] = {0, ((void)joinConds.push_back(e.asString()), 0)...};
    (void)dummy[0]; // to suppress warning
    if (joinConds.size() >= tables.size())
      joinConds.resize(tables.size() - 1);

    return *this;
  }
  std::vector<std::string> getJoinConds()
  {
    std::vector<std::string> results;
    for (const auto& e : joinConds)
      results.emplace_back(e);
    return results;
  }
  void clearJoinCond() { joinConds.clear(); }

  JoinedSource& orderBy(litesql::FieldType f, bool asc = true)
  {
    ordering = f.fullName();
    orderAsc = asc;
    return *this;
  }
  void clearOrdering()
  {
    ordering = "";
    orderAsc = true;
  }

  litesql::Records queryRaw(const litesql::Expr& e = litesql::Expr())
  {
    lastQuery = queryRawDry(e.asString());
    return db.query(lastQuery);
  }

  std::vector<tuple_type> query(const litesql::Expr& e = litesql::Expr())
  {
    return queryString(e.asString());
  }

  std::vector<tuple_type> queryString(const std::string& whereStr)
  {
    std::vector<tuple_type> results;
    lastQuery = queryRawDry(whereStr);
    auto recs = db.query(lastQuery);

    for (const auto& rec : recs) {
      combineTuple(results, rec);
    }
    return results;
  }

  std::string queryRawDry(const std::string& whereStr)
  {
    JoinedQuery sel;

    for (size_t i = 0; i < tables.size(); i++) {
      if (leftjoin && i > 0) {
        // std::string joinTable = "LEFT JOIN ";
        std::string joinTable = tables[i];
        if (joinConds.size() > i - 1 && joinConds[i - 1] != "True")
          joinTable += " ON " + joinConds[i - 1];
        sel.ljoin(joinTable);
      } else
        sel.source(tables[i]);
    }
    if (!whereStr.empty())
      sel.where(whereStr);
    for (size_t i = 0; i < fdatas.size(); i++)
      sel.result(fdatas[i].table() + "." + fdatas[i].name());

    if (!ordering.empty())
      sel.orderBy(ordering, orderAsc);

    return std::string(sel);
  }

  std::string getLastQuery() { return lastQuery; }

private:
  struct fill_field_type {
    fill_field_type(std::vector<litesql::FieldType>& fdatas_)
        : fdatasRef(fdatas_)
    {
    }
    template <typename U> void operator()(U& m) const
    {
      auto start = fdatasRef.size();
      U::first_type::getFieldTypes(fdatasRef);
      auto end = fdatasRef.size();
      m.second.first = start; // start index in fdata
      m.second.second = end;  // end + 1
    }

  private:
    std::vector<litesql::FieldType>& fdatasRef;
  };

  void setupInternal()
  {
    boost::fusion::for_each(typeMap, fill_field_type(fdatas));

    for (size_t i = 0; i < fdatas.size(); i++)
      if (tableSet.find(fdatas[i].table()) == tableSet.end()) {
        tables.push_back(fdatas[i].table());
        tableSet.insert(fdatas[i].table());
      }
  }

  struct separate_recs {
    using ConstIter = std::vector<std::string>::const_iterator;
    using DiffType = std::iterator_traits<ConstIter>::difference_type;
    separate_recs(litesql::Records& sepRecs_, ConstIter c)
        : sepRecsRef(sepRecs_), absStart(c)
    {
    }

    template <typename U> void operator()(U& m) const
    {
      litesql::Record sepRec;
      for (auto iter = absStart + static_cast<DiffType>(m.second.first);
           iter != absStart + static_cast<DiffType>(m.second.second); ++iter)
        sepRec.push_back(*iter);
      sepRecsRef.push_back(sepRec);
    }

  private:
    litesql::Records& sepRecsRef;
    ConstIter absStart;
  };

  void combineTuple(std::vector<tuple_type>& vecs, const litesql::Record& rec)
  {
    litesql::Records sepRecs;
    boost::fusion::for_each(typeMap, separate_recs(sepRecs, rec.cbegin()));
    for (auto& sepRec : sepRecs)
      if (sepRec[0] == "NULL") {
        sepRec[0] = "0";
        auto i = sepRec.begin();
        i++;
        for (; i != sepRec.end(); ++i)
          *i = "";
      }
    auto iter = sepRecs.cbegin();
    vecs.push_back(tuple_type{T(db, *iter++)...});
  }

  const litesql::Database& db;

  bool leftjoin;
  litesql::Split joinConds;
  std::string ordering;
  bool orderAsc = true;

  // helper data
  map_type typeMap;
  std::vector<litesql::FieldType> fdatas;
  litesql::Split tables;
  std::set<std::string> tableSet;

  std::string lastQuery;
};
