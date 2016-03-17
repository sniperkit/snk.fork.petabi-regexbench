// -*- c++ -*-
#ifndef REGEXBENCH_H
#define REGEXBENCH_H

#include <boost/timer/timer.hpp>

namespace regexbench {

class Engine;
class PcapSource;

boost::timer::cpu_times match(const Engine &, const PcapSource &);

}

#endif // REGEXBENCH_H
