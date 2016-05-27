// -*- c++ -*-
#ifndef REGEXBENCH_SESSION_H
#define REGEXBENCH_SESSION_H

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unordered_map>

#include "PcapSource.h"

#if defined(BOOST_BIG_ENDIAN)
constexpr uint16_t ETHERTYPE_IP_MD = 0x0800u;
constexpr uint16_t ETHERTYPE_ARP_MD = 0x0806u;
constexpr uint16_t ETHERTYPE_IPV6_MD = 0x86ddu;
#else
constexpr uint16_t ETHERTYPE_IP_MD = 0x0008u;
constexpr uint16_t ETHERTYPE_ARP_MD = 0x0608u;
constexpr uint16_t ETHERTYPE_IPV6_MD = 0xdd86u;
#endif

namespace regexbench {
  class Session {
  public:
    Session();
    ~Session() {}
  private:
    uint32_t id;
    bool direction;
    // matcher
  };

  inline uint16_t getEtherTypeMD(const uint8_t *rawpkt) {
    return reinterpret_cast<const ether_header *>(rawpkt)->ether_type;
  }

  uint32_t pkt_hash(const uint8_t *pkt) {
    uint32_t key;
    const uint8_t *nexthdr;
    uint16_t protocol;
    uint16_t ether_type = getEtherTypeMD(pkt);
    if (ether_type == ETHERTYPE_IP_MD) {
          const struct ip *ih =
            reinterpret_cast<const struct ip *>(pkt + sizeof(struct ether_header));
          protocol = ih->ip_p;
          key = protocol + ih->ip_src.s_addr + ih->ip_dst.s_addr;
          nexthdr = pkt + sizeof(struct ether_header) + (ih->ip_hl << 2);

    } else if (ether_type == ETHERTYPE_IPV6_MD) {
      const struct ip6_hdr *ipv6 = reinterpret_cast<const struct ip6_hdr *>(
                                                                            pkt + sizeof(struct ether_header));
      protocol = ipv6->ip6_nxt;
      key = protocol;
      int i;
      for (i = 0; i < 16; i++) {
        key += ipv6->ip6_dst.s6_addr[i] + ipv6->ip6_src.s6_addr[i];
      }
      nexthdr = pkt + sizeof(struct ether_header) + 40;
    } else {
      return 0;
    }
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
      const struct tcphdr *th = reinterpret_cast<const struct tcphdr *>(nexthdr);
      key += th->th_sport + th->th_dport;
    } else if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
      const struct icmp *icmph = reinterpret_cast<const struct icmp *>(nexthdr);
      key += icmph->icmp_type + icmph->icmp_code;
    }
    return key;
  }

  class SessionTable {
  public:
    SessionTable() = default;
    ~SessionTable() = default;
    void insert(const char *);
  private:
    std::unordered_multimap<uint32_t, Session, std::function<decltype(pkt_hash)>> sessionTable;
  };
} // namespace regexbench

#endif
