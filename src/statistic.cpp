#include "config.h"

#include <sys/resource.h>
#include <sys/time.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include "regexbench.h"

using namespace regexbench;

static std::map<std::string, size_t>
make_statistic(const uint32_t sec, const struct ResultInfo& stat);
static struct ResultInfo realtime(std::vector<MatchResult>& results);
static struct ResultInfo total(std::vector<MatchResult>& results);

void regexbench::statistic(const uint32_t sec,
                           std::vector<MatchResult>& results, realtimeFunc func)
{
  struct ResultInfo stat = sec ? realtime(results) : total(results);
  std::map<std::string, size_t> m = make_statistic(sec, stat);

  if (func == nullptr)
    realtimeReport(m);
  else
    func(m);
}

static struct ResultInfo realtime(std::vector<MatchResult>& results)
{
  struct ResultInfo stat;

  for (auto& r : results) {
    struct ResultInfo cur = r.cur;
    struct ResultInfo& old = (r.old);

    stat.nmatches += cur.nmatches - old.nmatches;
    stat.nmatched_pkts += cur.nmatched_pkts - old.nmatched_pkts;
    stat.npkts += cur.npkts - old.npkts;
    stat.nbytes += cur.nbytes - old.nbytes;

    old.nmatches = cur.nmatches;
    old.nmatched_pkts = cur.nmatched_pkts;
    old.npkts = cur.npkts;
    old.nbytes = cur.nbytes;
  }

  return stat;
}

static struct ResultInfo total(std::vector<MatchResult>& results)
{
  struct ResultInfo stat;

  for (auto& r : results) {
    const struct ResultInfo& cur = r.cur;

    stat.nmatches += cur.nmatches;
    stat.nmatched_pkts += cur.nmatched_pkts;
    stat.npkts += cur.npkts;
    stat.nbytes += cur.nbytes;
  }

  return stat;
}

static std::map<std::string, size_t>
make_statistic(const uint32_t sec, const struct ResultInfo& stat)
{
  std::map<std::string, size_t> m;

  m.insert(std::make_pair("Sec", sec));
  m.insert(std::make_pair("Matches", stat.nmatches));
  m.insert(std::make_pair("MatchedPackets", stat.nmatched_pkts));
  m.insert(std::make_pair("Packets", stat.npkts));
  m.insert(std::make_pair("Bytes", stat.nbytes));

  return m;
}
