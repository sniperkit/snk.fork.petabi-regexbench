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
make_statistic(const uint32_t sec, const size_t usec,
               const struct ResultInfo& stat, const struct ResultInfo& total);
static struct ResultInfo realtime(std::vector<MatchResult>& results);
static struct ResultInfo total(std::vector<MatchResult>& results);

void regexbench::statistic(const uint32_t sec, timeval& begin,
                           std::vector<MatchResult>& results, realtimeFunc func,
                           void* p)
{
  struct ResultInfo stat = realtime(results);
  struct ResultInfo tstat = total(results);
  size_t usec = 0;
  timeval diff;

  for (auto& r : results) {
    // not ended yet.
    if (r.endtime.tv_sec == 0 && r.endtime.tv_usec == 0) {
      usec = 0;
      break;
    }

    timersub(&(r.endtime), &begin, &diff);

    // if sec is less than 0, then already finished before begin time.
    if (diff.tv_sec < 0)
      continue;

    size_t m_usec = static_cast<size_t>(diff.tv_sec * 1e+6 + diff.tv_usec);
    if (usec < m_usec)
      usec = m_usec;
  }

  if (usec == 0) {
    timeval end;

    gettimeofday(&end, NULL);
    timersub(&end, &begin, &diff);

    begin = end;
    usec = static_cast<size_t>(diff.tv_sec * 1e+6 + diff.tv_usec);
  }

  // std::cout << std::fixed << std::setprecision(6) << "usec : " << usec <<
  // std::endl;

  std::map<std::string, size_t> m = make_statistic(sec, usec, stat, tstat);

  // if the number of processed packets is 0, then complete.
  if (func && m["Packets"] != 0)
    func(m, p);
}

static struct ResultInfo realtime(std::vector<MatchResult>& results)
{
  struct ResultInfo stat;

  for (auto& r : results) {
    const auto cur = r.cur;
    auto& old = (r.old);

    stat.nmatches += cur.nmatches - old.nmatches;
    stat.nmatched_pkts += cur.nmatched_pkts - old.nmatched_pkts;
    stat.npkts += cur.npkts - old.npkts;
    stat.nbytes += cur.nbytes - old.nbytes;

    old = cur;
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
make_statistic(const uint32_t sec, const size_t usec,
               const struct ResultInfo& stat, const struct ResultInfo& total)
{
  std::map<std::string, size_t> m;

  m["Sec"] = sec;
  m["Usec"] = usec;
  m["Matches"] = stat.nmatches;
  m["MatchedPackets"] = stat.nmatched_pkts;
  m["Packets"] = stat.npkts;
  m["Bytes"] = stat.nbytes;
  m["TotalMatches"] = total.nmatches;
  m["TotalMatchedPackets"] = total.nmatched_pkts;
  m["TotalPackets"] = total.npkts;
  m["TotalBytes"] = total.nbytes;

  return m;
}
