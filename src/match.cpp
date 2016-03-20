#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "Engine.h"
#include "PcapSource.h"
#include "regexbench.h"

using namespace regexbench;

MatchResult regexbench::match(Engine &engine,
                              const PcapSource &src,
                              long repeat) {
  struct rusage begin, end;
  MatchResult result;
  getrusage(RUSAGE_SELF, &begin);
  for (long i = 0; i < repeat; ++i) {
    for (const auto &packet : src) {
      uint16_t offset = 0;
      uint16_t ether_type =
        ntohs(reinterpret_cast<const ether_header *>(packet.data())->ether_type);
      if (ether_type == ETHERTYPE_VLAN) {
        offset = 4;
        ether_type =
          ntohs(reinterpret_cast<const ether_header *>(packet.data() + offset)->ether_type);
      }
      switch (ether_type) {
      case ETHERTYPE_IP: {
        offset += sizeof(ether_header);
        const ip *ih = reinterpret_cast<const ip *>(packet.data() + offset);
        offset += ih->ip_hl << 2;
        switch (ih->ip_p) {
        case IPPROTO_TCP:
          offset += reinterpret_cast<const tcphdr *>(packet.data() + offset)->th_off << 2;
          break;
        case IPPROTO_UDP:
          offset += sizeof(udphdr);
          break;
        case IPPROTO_ICMP:
          offset += ICMP_MINLEN;
          break;
        default:
          break;
        }
      }
        break;
      case ETHERTYPE_IPV6: {
        offset += sizeof(ether_header) + sizeof(ip6_hdr);
        const ip6_hdr *ih6 = reinterpret_cast<const ip6_hdr *>(packet.data() + offset);
        switch (ih6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case IPPROTO_TCP:
          offset += reinterpret_cast<const tcphdr *>(packet.data() + offset)->th_off << 2;
          break;
        case IPPROTO_UDP:
          offset += sizeof(udphdr);
          break;
        case IPPROTO_ICMP:
          offset += ICMP_MINLEN;
          break;
        default:
          break;
        }
      }
        break;
      default:
        break;
      }
      if (engine.match(packet.data() + offset, packet.size() - offset))
        result.nmatches++;
    }
  }
  getrusage(RUSAGE_SELF, &end);
  timersub(&(end.ru_utime), &(begin.ru_utime), &result.udiff);
  timersub(&(end.ru_stime), &(begin.ru_stime), &result.sdiff);
  return result;
}
