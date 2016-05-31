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
#include <pius/session.h>
#include <pius/netmap.h>



namespace regexbench {

  constexpr inline uint16_t EXT_SPORT(const uint8_t *pkt, uint16_t size_iphdr) {
    return ntohs(*reinterpret_cast<const uint16_t *>(pkt + size_iphdr + ETHER_HDR_LEN + offsetof(struct tcphdr, th_sport)));
  }

  constexpr inline uint16_t EXT_DPORT(const uint8_t *pkt, uint16_t size_iphdr) {
    return ntohs(*reinterpret_cast<const uint16_t *>(pkt + size_iphdr + ETHER_HDR_LEN + offsetof(struct tcphdr, th_dport)));
  }


  constexpr inline uint32_t EXT_SIP(const uint8_t *pkt) {
    return ntohl(*reinterpret_cast<const uint16_t *>(pkt + ETHER_HDR_LEN + offsetof(struct ip, ip_src)));
  }

  constexpr inline uint32_t EXT_DIP(const uint8_t *pkt) {
    return ntohl(*reinterpret_cast<const uint16_t *>(pkt + ETHER_HDR_LEN + offsetof(struct ip, ip_dst)));
  }

  inline const struct ip6_addr *EXT_SIP6(const uint8_t *pkt) {
    return reinterpret_cast<const struct ip6_addr *>(pkt + ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_src));
  }

  inline const struct ip6_addr *EXT_DIP6(const uint8_t *pkt) {
    return reinterpret_cast<const struct ip6_addr *>(pkt + ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_dst));
  }


  inline uint8_t EXT_ICMP_TP(const uint8_t *pkt, uint16_t size_iphdr) {
    return *(pkt + size_iphdr + ETHER_HDR_LEN +
             offsetof(struct icmp, icmp_type));
  }

  inline uint8_t EXT_ICMP_CD(const uint8_t *pkt, uint16_t size_iphdr) {
    return *(pkt + size_iphdr + ETHER_HDR_LEN +
             offsetof(struct icmp, icmp_code));
  }

  class Session {
  public:
    Session() = delete;
    Session(const uint8_t *pkt);
    bool operator==(const Session &);
    uint32_t getHashval() const { return s.hashval; }
    ~Session() {}
  private:
    SESSION s;
    uint16_t ether_type;
    uint16_t pl_off;
    //static uint16_t getPLOff(uint16_t);
    bool direction;
    int cmp_in6_addr(const struct in6_addr *a1, const struct in6_addr *a2) {
      int i;
    for (i = 0; i < 16; i++) {
      if (a1->s6_addr[i] != a2->s6_addr[i]) {
        return 0;
      }
    }
    return 1;
  }


    // matcher
  };

  uint32_t pkt_hash(const uint8_t *pkt);

  class SessionTable {
  public:
    SessionTable() = default;
    ~SessionTable() = default;
    void insert(const uint8_t *);
    void find(const uint8_t *);
  private:
    std::unordered_multimap<uint32_t, Session> sessionTable;
  };
} // namespace regexbench

#endif
