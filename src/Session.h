// -*- c++ -*-
#ifndef REGEXBENCH_SESSION_H
#define REGEXBENCH_SESSION_H

#include <netinet/in.h>
#include <stddef.h>
#include <sys/types.h>

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

namespace regexbench {
#ifndef __linux__
constexpr
#endif
    inline uint16_t
    EXT_SPORT(const char* pkt, uint16_t size_iphdr)
{
  return ntohs(
      *reinterpret_cast<const uint16_t*>(pkt + size_iphdr + ETHER_HDR_LEN +
#ifdef __linux__
                                         offsetof(struct tcphdr, source)
#else
                                         offsetof(struct tcphdr, th_sport)
#endif
                                             ));
}

#ifndef __linux__
constexpr
#endif
    inline uint16_t
    EXT_DPORT(const char* pkt, uint16_t size_iphdr)
{
  return ntohs(*reinterpret_cast<const uint16_t*>(pkt + size_iphdr +
                                                  ETHER_HDR_LEN +
#ifdef __linux__
                                                  offsetof(struct tcphdr, dest)
#else
                                                  offsetof(struct tcphdr,
                                                           th_dport)
#endif
                                                      ));
}

#ifndef __linux__
constexpr
#endif
    inline uint32_t
    EXT_SIP(const char* pkt)
{
  return ntohl(*reinterpret_cast<const uint16_t*>(pkt + ETHER_HDR_LEN +
                                                  offsetof(struct ip, ip_src)));
}

#ifndef __linux__
constexpr
#endif
    inline uint32_t
    EXT_DIP(const char* pkt)
{
  return ntohl(*reinterpret_cast<const uint16_t*>(pkt + ETHER_HDR_LEN +
                                                  offsetof(struct ip, ip_dst)));
}

inline const struct ip6_addr* EXT_SIP6(const char* pkt)
{
  return reinterpret_cast<const struct ip6_addr*>(
      pkt + ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_src));
}

inline const struct ip6_addr* EXT_DIP6(const char* pkt)
{
  return reinterpret_cast<const struct ip6_addr*>(
      pkt + ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_dst));
}

inline uint8_t EXT_ICMP_TP(const char* pkt, uint16_t size_iphdr)
{
  return *reinterpret_cast<const uint8_t*>(pkt + size_iphdr + ETHER_HDR_LEN +
                                           offsetof(struct icmp, icmp_type));
}

inline uint8_t EXT_ICMP_CD(const char* pkt, uint16_t size_iphdr)
{
  return *reinterpret_cast<const uint8_t*>(pkt + size_iphdr + ETHER_HDR_LEN +
                                           offsetof(struct icmp, icmp_code));
}

constexpr inline int cmp_in6_addr(const struct in6_addr* a1,
                                  const struct in6_addr* a2)
{
  for (size_t i = 0; i < 16; i++)
    if (a1->s6_addr[i] != a2->s6_addr[i])
      return 0;
  return 1;
}

template <typename T> class AddrPair {
public:
  T src;
  T dst;
};

inline bool operator==(const AddrPair<in_addr>& lhs,
                       const AddrPair<in_addr>& rhs)
{
  return *reinterpret_cast<const uint64_t*>(&lhs) ==
         *reinterpret_cast<const uint64_t*>(&rhs);
};

class Session {
public:
  Session() = delete;
  Session(const char* pkt);
  bool operator==(const Session&);
  uint32_t getHashval() const { return hashval; }
  void setSession(uint32_t sid) { session_idx = sid; }
  uint32_t getSession() const { return session_idx; }

private:
  union {
    class AddrPair<in_addr> ipv4;
    class AddrPair<in6_addr> ipv6;
  } addr;
  union {
    uint16_t sport;
    uint16_t icmp_tp;
  } si;
  union {
    uint16_t dport;
    uint16_t icmp_cd;
  } di;
  uint32_t hashval;
  uint32_t session_idx;
  uint16_t ether_type;
  uint16_t pl_off;
  uint32_t matcher_idx;
  uint8_t protocol;
  uint8_t ver; /* IPv4 or IPv6 */
  char paddings[2];
};

class SessionTable {
public:
  SessionTable() = default;
  ~SessionTable() = default;
  bool find(Session&, size_t&);
  static uint32_t getSessionNum() { return nsessions; }

private:
  std::unordered_multimap<uint32_t, Session> sessionTable;
  static uint32_t nsessions;
};
} // namespace regexbench

#endif
