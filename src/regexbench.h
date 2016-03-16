// -*- c++ -*-
#ifndef REGEXBENCH_H
#define REGEXBENCH_H

#include <boost/timer/timer.hpp>

namespace regexbench {

class PcapSource;

boost::timer::cpu_times match(const PcapSource &);

}

#endif // REGEXBENCH_H
