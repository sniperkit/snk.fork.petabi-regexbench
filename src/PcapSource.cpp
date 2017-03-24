#include <array>
#include <string>

#include <pcap/pcap.h>

#include "PcapSource.h"

using namespace regexbench;

class Pcap {
public:
  Pcap() = delete;
  explicit Pcap(const std::string& filename);
  Pcap(const Pcap&) = delete;
  Pcap(Pcap&& o) : handle(o.handle) { o.handle = nullptr; }
  ~Pcap()
  {
    if (handle)
      pcap_close(handle);
  }
  Pcap& operator=(const Pcap&) = delete;
  Pcap& operator=(Pcap&& o)
  {
    if (handle)
      pcap_close(handle);
    handle = o.handle;
    return *this;
  }

  pcap_t* operator()() { return handle; }

private:
  pcap_t* handle;
};

Pcap::Pcap(const std::string& filename)
{
  std::array<char, PCAP_ERRBUF_SIZE> errbuf;
  handle = pcap_open_offline(filename.data(), errbuf.data());
  if (handle == nullptr)
    throw std::runtime_error(errbuf.data());
}

PcapSource::PcapSource(const std::string& filename) : nbytes(0)
{
  Pcap pcap(filename);
  pcap_pkthdr* header;
  const unsigned char* packet;
  int result;
  while ((result = pcap_next_ex(pcap(), &header, &packet)) == 1) {
    packets.emplace_back(
        std::string(reinterpret_cast<const char*>(packet), header->caplen));
    nbytes += header->len;
  }
}
