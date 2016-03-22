#include <arpa/inet.h>
#include <netinet/in.h>

#include <array>
#include <string>

#include <pcap/pcap.h>

#include "PcapSource.h"

using namespace regexbench;

class Pcap {
public:
  Pcap() = delete;
  explicit Pcap(const std::string &filename);
  Pcap(const Pcap &) = delete;
  Pcap(Pcap &&o) : handle(o.handle) { o.handle = nullptr; }
  ~Pcap() { if (handle) pcap_close(handle); }
  Pcap &operator=(const Pcap &) = delete;
  Pcap &operator=(Pcap &&o) {
    if (handle) pcap_close(handle);
    handle = o.handle;
    return *this;
  }

  pcap_t *operator()() { return handle; }

private:
  pcap_t *handle;
};

Pcap::Pcap(const std::string &filename) {
  std::array<char, PCAP_ERRBUF_SIZE> errbuf;
  handle = pcap_open_offline(filename.data(), errbuf.data());
  if (handle == nullptr)
    throw std::runtime_error(errbuf.data());
}

PcapSource::PcapSource(const std::string &filename) : nbytes(0) {
  Pcap pcap(filename);
  pcap_pkthdr *header;
  const unsigned char *packet;
  int result;
  while ((result = pcap_next_ex(pcap(), &header, &packet)) == 1) {
    packets.emplace_back(
        std::string(reinterpret_cast<const char *>(packet), header->caplen));
    nbytes += header->caplen + 24;
  }
}

PcapGenerator::PcapGenerator(const std::string &filename,
                             std::vector<std::string> &tokenList,
                             size_t nb = 1024, size_t np = 1024) :
  nbytes(nb), npackets(np){
  std::array<char, PCAP_ERRBUF_SIZE> errbuf;
  pcap_t *handle = pcap_open_dead(0x1, 65535);
  pcap_dumper_t *pcap_hdl;
  char buf[65535];

  if (handle == nullptr)
    throw std::runtime_error(errbuf.data());
  pcap_hdl = pcap_dump_open(handle, filename.c_str());
  if (pcap_hdl == nullptr)
    throw std::runtime_error(errbuf.data());

  struct pcap_pkthdr phdr;
  phdr.caplen = phdr.len = static_cast<uint32_t>(nbytes);

  memset(&buf[0], 0xff, 6);
  memset(&buf[6], 0x10, 6);
  *reinterpret_cast<uint16_t *>(&buf[12]) = htons(0x0800);

  // IPv4 header
  *reinterpret_cast<uint16_t *>(&buf[14]) = htons(0x4500);
  *reinterpret_cast<uint16_t *>(&buf[16]) = htons(nbytes - 14);
  *reinterpret_cast<uint16_t *>(&buf[18]) = 0;   // ip_id
  *reinterpret_cast<uint16_t *>(&buf[20]) = 0;   // ip_off
  *reinterpret_cast<uint8_t *>(&buf[22]) = 0x10; // ttl
  //if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
  //assert(false);                                   // TODO
  *reinterpret_cast<uint8_t *>(&buf[23]) = IPPROTO_TCP; // protocol
  *reinterpret_cast<uint16_t *>(&buf[24]) = 0;    // csum (TODO)
  *reinterpret_cast<uint32_t *>(&buf[26]) = 0;//(srcip ? srcip->s_addr : 0);
  *reinterpret_cast<uint32_t *>(&buf[30]) = 0;//(dstip ? dstip->s_addr : 0);

  //if (proto == IPPROTO_TCP) {
    // TCP header
  *reinterpret_cast<uint16_t *>(&buf[34]) = htons(80);
  *reinterpret_cast<uint16_t *>(&buf[36]) = htons(8080);
  *reinterpret_cast<uint32_t *>(&buf[38]) = 0;             // seq num
  *reinterpret_cast<uint32_t *>(&buf[42]) = 0;             // ack num
  *reinterpret_cast<uint16_t *>(&buf[46]) = htons(0x5000); // data offset
  // flags
  *reinterpret_cast<uint16_t *>(&buf[48]) = 0;             // window
  *reinterpret_cast<uint32_t *>(&buf[50]) = 0; // csum, urgent pointer
  /*} else if (proto == IPPROTO_UDP) {
    // UDP header
    *reinterpret_cast<uint16_t *>(&buf[34]) = htons(sport);
    *reinterpret_cast<uint16_t *>(&buf[36]) = htons(dport);
    *reinterpret_cast<uint16_t *>(&buf[38]) =
        htons(framelen - 14 - 20);                  // udp len
    *reinterpret_cast<uint16_t *>(&buf[40]) = 0; // csum (TODO)
    }*/

  auto tok = tokenList.begin();
  auto mark = tokenList.end();
  for (size_t i = 0; i < npackets; ++i) {
    size_t len = 54;
    while (len < nbytes - 1) {
      if (len + tok->size() < nbytes) {
        strcpy(&buf[len], tok->c_str());
        len += tok->size();
        tok++;
        mark++;
      } else {
        if (tok == tokenList.end()) {
          len = nbytes;
        }
        tok++;
      }
      if (tok == tokenList.end())
        tok = tokenList.begin();
    }
    mark++;
    if (mark == tokenList.end())
      mark = tokenList.begin();
    pcap_dump(reinterpret_cast<u_char *>(pcap_hdl), &phdr, reinterpret_cast<u_char *>(buf));
  }

  pcap_dump_close(pcap_hdl);
  pcap_close(handle);
}
