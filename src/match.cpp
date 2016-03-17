#include <sys/resource.h>
#include <sys/time.h>

#include "Engine.h"
#include "PcapSource.h"
#include "regexbench.h"

using namespace regexbench;

MatchResult regexbench::match(const Engine &engine,
                              const PcapSource &src) {
  struct rusage begin, end;
  MatchResult result;
  getrusage(RUSAGE_SELF, &begin);
  for (auto packet : src) {
    if (engine.match(packet.data(), packet.size()))
      result.nmatches++;
  }
  getrusage(RUSAGE_SELF, &end);
  timersub(&(end.ru_utime), &(begin.ru_utime), &result.udiff);
  timersub(&(end.ru_stime), &(begin.ru_stime), &result.sdiff);
  return result;
}
