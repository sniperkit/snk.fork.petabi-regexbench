// -*- c++ -*-
#ifndef PCAPSOURCE_H
#define PCAPSOURCE_H

#include <vector>

namespace regexbench {

class PcapSource {
public:
  PcapSource() = delete;
  explicit PcapSource(const std::string &filename);
  PcapSource(const PcapSource &) = default;
  PcapSource(PcapSource &&) = default;
  ~PcapSource() = default;
  PcapSource &operator=(const PcapSource &) = default;
  PcapSource &operator=(PcapSource &&) = default;

private:
  std::vector<std::string> packets;
};

} // namespace regexbench

#endif // PCAPSOURCE_H
