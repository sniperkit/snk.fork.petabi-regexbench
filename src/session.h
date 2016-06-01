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

  constexpr inline uint16_t EXT_SPORT(const char *pkt, uint16_t size_iphdr) {
    return ntohs(*reinterpret_cast<const uint16_t *>(pkt + size_iphdr + ETHER_HDR_LEN + offsetof(struct tcphdr, th_sport)));
  }

  constexpr inline uint16_t EXT_DPORT(const char *pkt, uint16_t size_iphdr) {
    return ntohs(*reinterpret_cast<const uint16_t *>(pkt + size_iphdr + ETHER_HDR_LEN + offsetof(struct tcphdr, th_dport)));
  }


  constexpr inline uint32_t EXT_SIP(const char *pkt) {
    return ntohl(*reinterpret_cast<const uint16_t *>(pkt + ETHER_HDR_LEN + offsetof(struct ip, ip_src)));
  }

  constexpr inline uint32_t EXT_DIP(const char *pkt) {
    return ntohl(*reinterpret_cast<const uint16_t *>(pkt + ETHER_HDR_LEN + offsetof(struct ip, ip_dst)));
  }

  inline const struct ip6_addr *EXT_SIP6(const char *pkt) {
    return reinterpret_cast<const struct ip6_addr *>(pkt + ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_src));
  }

  inline const struct ip6_addr *EXT_DIP6(const char *pkt) {
    return reinterpret_cast<const struct ip6_addr *>(pkt + ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_dst));
  }


  inline uint8_t EXT_ICMP_TP(const char *pkt, uint16_t size_iphdr) {
    return *reinterpret_cast<const uint8_t *>(pkt + size_iphdr + ETHER_HDR_LEN +
             offsetof(struct icmp, icmp_type));
  }

  inline uint8_t EXT_ICMP_CD(const char *pkt, uint16_t size_iphdr) {
    return *reinterpret_cast<const uint8_t*>(pkt + size_iphdr + ETHER_HDR_LEN +
             offsetof(struct icmp, icmp_code));
  }

  class Session {
  public:
    Session() = delete;
    Session(const char *pkt);
    bool operator==(const Session &);
    uint32_t getHashval() const { return s.hashval; }
    bool getDirection() const { return direction; }
    void setMatcher(uint32_t);
    uint32_t getMatcher() const ;
    uint16_t getPLOff() const { return pl_off; }
  private:
    SESSION s;
    uint16_t ether_type;
    uint16_t pl_off;
    uint32_t matcher_idx;
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
    char paddings[55];
  };

  uint32_t pkt_hash(const char *pkt);

  class SessionTable {
  public:
    SessionTable() = default;
    ~SessionTable() = default;
    bool find(Session &);
    static uint32_t nextMatcher();
  private:
    std::unordered_multimap<uint32_t, Session> sessionTable;
    static uint32_t nmatchers;
  };
} // namespace regexbench

#endif
