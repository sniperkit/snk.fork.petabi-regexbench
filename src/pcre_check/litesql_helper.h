#include <set>
#include <string>
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
  typedef boost::fusion::map<boost::fusion::pair<T, std::pair<int, int>>...>
      map_type;

  JoinedSource(const litesql::Database& db_, bool leftjoin = false)
      : db(db_), typeMap(boost::fusion::make_pair<T>(std::make_pair(0, 0))...)
  {
    setupInternal();
  }

  litesql::Records queryRaw(const litesql::Expr& e = litesql::Expr())
  {
    JoinedQuery sel;

    for (size_t i = 0; i < tables.size(); i++)
      sel.source(tables[i]);
    sel.where(e.asString());
    for (size_t i = 0; i < fdatas.size(); i++)
      sel.result(fdatas[i].table() + "." + fdatas[i].name());

    return db.query(sel);
  }

private:
  struct fill_field_type {
    fill_field_type(std::vector<litesql::FieldType>& fdatas_)
        : fdatasRef(fdatas_)
    {
    }
    template <typename U> void operator()(U&) const
    {
      U::first_type::getFieldTypes(fdatasRef);
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

  const litesql::Database& db;

  // helper data
  map_type typeMap;
  std::vector<litesql::FieldType> fdatas;
  litesql::Split tables;
  std::set<std::string> tableSet;
};
