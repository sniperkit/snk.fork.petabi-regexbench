#include "Session.h"

#include <string>

using namespace regexbench;

Session::Session(const char* pkt) : hashval(0), matcher_idx(0)
{
  ether_type = ntohs(reinterpret_cast<const ether_header*>(pkt)->ether_type);
  uint16_t size_iphdr = 0;
  if (ether_type == ETHERTYPE_IPV6) {
    protocol = reinterpret_cast<const ip6_hdr*>(pkt + ETHER_HDR_LEN)->ip6_nxt;

    size_iphdr = 40;
    memcpy(&addr.ipv6.src, EXT_SIP6(pkt), 16);
    memcpy(&addr.ipv6.dst, EXT_DIP6(pkt), 16);

    auto oft = ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_dst);
    for (size_t i = 0; i < 16; i += 4)
      hashval ^= *reinterpret_cast<const uint32_t*>(&pkt[oft + i]);

    oft = ETHER_HDR_LEN + offsetof(struct ip6_hdr, ip6_src);
    for (size_t i = 0; i < 16; i += 4)
      hashval ^= *reinterpret_cast<const uint32_t*>(&pkt[oft + i]);

    hashval ^= protocol;
  } else if (ether_type == ETHERTYPE_IP) {
    auto ih = reinterpret_cast<const ip*>(pkt + ETHER_HDR_LEN);
    protocol = ih->ip_p;
    size_iphdr = static_cast<uint16_t>(ih->ip_hl << 2);
    addr.ipv4.src.s_addr = EXT_SIP(pkt);
    addr.ipv4.dst.s_addr = EXT_DIP(pkt);

    hashval ^= addr.ipv4.src.s_addr;
    hashval ^= addr.ipv4.dst.s_addr;
    hashval ^= protocol;
  }

  if (protocol == IPPROTO_ICMP) {
    si.icmp_tp = EXT_ICMP_TP(pkt, size_iphdr);
    di.icmp_cd = EXT_ICMP_CD(pkt, size_iphdr);
    hashval ^= static_cast<uint32_t>(si.icmp_tp) << 16 | di.icmp_cd;
  } else {
    si.sport = EXT_SPORT(pkt, size_iphdr);
    di.dport = EXT_DPORT(pkt, size_iphdr);
    hashval ^= static_cast<uint32_t>(si.sport) << 16 | di.dport;
  }
}

bool Session::operator==(const Session& rhs)
{
  if (ether_type != rhs.ether_type || protocol != rhs.protocol)
    return false;
  if (ether_type == ETHERTYPE_IP) {
    if (addr.ipv4.src.s_addr == rhs.addr.ipv4.src.s_addr &&
        addr.ipv4.dst.s_addr == rhs.addr.ipv4.dst.s_addr) {
      if (__builtin_expect(protocol == IPPROTO_ICMP, false)) {
        if (si.icmp_tp == rhs.si.icmp_tp && di.icmp_cd == rhs.di.icmp_cd) {
          return true;
        }
      } else if (si.sport == rhs.si.sport && di.dport == rhs.di.dport) {
        return true;
      }
    }
    return false;
  }

  // IPv6
  if (cmp_in6_addr(&addr.ipv6.src, &rhs.addr.ipv6.src) &&
      cmp_in6_addr(&addr.ipv6.dst, &rhs.addr.ipv6.dst)) {
    if (__builtin_expect(protocol == IPPROTO_ICMP, false)) {
      if (si.icmp_tp == rhs.si.icmp_tp && di.icmp_cd == rhs.di.icmp_cd) {
        return true;
      }
    } else if (si.sport == rhs.si.sport && di.dport == rhs.di.dport) {
      return true;
    }
  }
  return false;
}

bool SessionTable::find(Session& s, size_t& sid)
{
  auto its = sessionTable.equal_range(s.getHashval());
  auto it = its.first;
  for (; it != its.second; ++it) {
    if (s == it->second) {
      sid = it->second.getSession();
      return true;
    }
  }
  if (it == its.second) {
    s.setSession(nsessions++);
    sessionTable.insert(std::make_pair(s.getHashval(), s));
    sid = s.getSession();
  }
  return false;
}

uint32_t SessionTable::nsessions = 0;
