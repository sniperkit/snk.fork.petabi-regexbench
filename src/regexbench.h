// -*- c++ -*-
#ifndef REGEXBENCH_H
#define REGEXBENCH_H

#include <boost/timer/timer.hpp>

namespace regexbench {

class Engine;
class PcapSource;

struct MatchResult {
MatchResult() : nmatches(0) {}

struct timeval udiff;
struct timeval sdiff;
size_t nmatches;
};

MatchResult match(const Engine &, const PcapSource &);

}

#endif // REGEXBENCH_H
