// -*- c++ -*-
#ifndef PCAPSOURCE_H
#define PCAPSOURCE_H

#include <vector>

namespace regexbench {

class PcapSource {
public:
  PcapSource() = delete;
  explicit PcapSource(const std::string& filename);
  PcapSource(const PcapSource&) = default;
  PcapSource(PcapSource&&) = default;
  ~PcapSource() = default;
  PcapSource& operator=(const PcapSource&) = default;
  PcapSource& operator=(PcapSource&&) = default;
  const std::string& operator[](size_t idx) const { return packets[idx]; }

  auto begin() const { return packets.begin(); }
  auto end() const { return packets.end(); }

  size_t getNumberOfBytes() const { return nbytes; }
  size_t getNumberOfPackets() const { return packets.size(); }

private:
  std::vector<std::string> packets;
  size_t nbytes;
};

} // namespace regexbench

#endif // PCAPSOURCE_H
