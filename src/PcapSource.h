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

  auto begin() const { return packets.begin(); }
  auto end() const {return packets.end(); }

  size_t getNumberOfBytes() const { return nbytes; }
  size_t getNumberOfPackets() const { return packets.size(); }

private:
  std::vector<std::string> packets;
  size_t nbytes;
};

class PcapGenerator {
public:
  PcapGenerator() = delete;
  explicit PcapGenerator(const std::string &filename,
                         std::vector<std::string> &tokList,
                         size_t nbytes, size_t npackets);
  PcapGenerator(const PcapGenerator &) = default;
  PcapGenerator(PcapGenerator &&) = default;
  ~PcapGenerator() = default;
  PcapGenerator &operator=(const PcapGenerator &) = default;
  PcapGenerator &operator=(PcapGenerator &&) = default;

  size_t getNumberOfBytes() const { return nbytes; }
  size_t getNumberOfPackets() const { return npackets; }

private:
  size_t nbytes;
  size_t npackets;
};

} // namespace regexbench

#endif // PCAPSOURCE_H
