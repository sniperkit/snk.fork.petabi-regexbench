#include <boost/timer/timer.hpp>

#include "PcapSource.h"
#include "regexbench.h"

using namespace regexbench;

boost::timer::cpu_times regexbench::match(const PcapSource &src) {
  size_t npkts = 0;
  boost::timer::cpu_timer timer;
  for (auto packet : src) {
    npkts++;
  }
  timer.stop();
  return timer.elapsed();
}
