#include <boost/timer/timer.hpp>

#include "Engine.h"
#include "PcapSource.h"
#include "regexbench.h"

using namespace regexbench;

boost::timer::cpu_times regexbench::match(const Engine &engine,
                                          const PcapSource &src) {
  size_t nmatches = 0;
  boost::timer::cpu_timer timer;
  for (auto packet : src) {
    if (engine.match(packet.data(), packet.size()))
      nmatches++;
  }
  timer.stop();
  return timer.elapsed();
}
