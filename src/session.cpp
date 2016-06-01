#include "session.h"

#include <iostream>
#include <string>

using namespace regexbench;

Session::Session(const char *pkt) : matcher_idx(0) {
  s.hashval = pius::computeRSSHash(reinterpret_cast<const uint8_t *>(pkt));

  ether_type = ntohs(reinterpret_cast<const ether_header *>(pkt)->ether_type);
  uint16_t size_iphdr = 0;
  if (ether_type == ETHERTYPE_IPV6) {
     s.protocol =
      reinterpret_cast<const ip6_hdr *>(pkt + ETHER_HDR_LEN)
      ->ip6_nxt;

     size_iphdr = 40;
     memcpy(&s.addr.ipv6.src, EXT_SIP6(pkt), 16);
     memcpy(&s.addr.ipv6.dst, EXT_DIP6(pkt), 16);
  } else if (ether_type == ETHERTYPE_IP) {
    auto ih = reinterpret_cast<const ip *>(pkt + ETHER_HDR_LEN);
    s.protocol = ih->ip_p;
    size_iphdr = static_cast<uint16_t>(ih->ip_hl << 2);
    s.addr.ipv4.src.s_addr = EXT_SIP(pkt);
    s.addr.ipv4.dst.s_addr = EXT_DIP(pkt);
  }

  if (s.protocol == IPPROTO_ICMP) {
    s.si.icmp_tp = EXT_ICMP_TP(pkt, size_iphdr);
    s.di.icmp_cd = EXT_ICMP_CD(pkt, size_iphdr);
  } else {
    s.si.sport = EXT_SPORT(pkt, size_iphdr);
    s.di.dport = EXT_DPORT(pkt, size_iphdr);
  }

  // pl_off = getPLOff(s.protocol);
}

bool Session::operator==(const Session &rhs) {
  if (ether_type != rhs.ether_type || s.protocol != rhs.s.protocol)
    return false;
  if (ether_type == ETHERTYPE_IP) {
    if (s.addr.ipv4.src.s_addr == rhs.s.addr.ipv4.src.s_addr &&
        s.addr.ipv4.dst.s_addr == rhs.s.addr.ipv4.dst.s_addr) {
      if (__builtin_expect(s.protocol == IPPROTO_ICMP, false)) {
        if (s.si.icmp_tp == rhs.s.si.icmp_tp &&
            s.di.icmp_cd == rhs.s.di.icmp_cd) {
          direction = false;
          return true;
        }
      } else if (s.si.sport == rhs.s.si.sport &&
                 s.di.dport == rhs.s.di.dport) {
        direction = false;
        return true;
      }
    }
    if (s.addr.ipv4.src.s_addr == rhs.s.addr.ipv4.dst.s_addr &&
        s.addr.ipv4.dst.s_addr == rhs.s.addr.ipv4.src.s_addr) {
      if (__builtin_expect(s.protocol == IPPROTO_ICMP, false)) {
        if (s.si.icmp_tp == rhs.s.si.icmp_tp &&
            s.di.icmp_cd == rhs.s.di.icmp_cd) {
          direction = true;
          return true;
        }
      } else if (s.si.sport == rhs.s.di.dport &&
                 s.di.dport == rhs.s.si.sport) {
        direction = true;
        return true;
      }
    }
    return false;
  }

  // IPv6
  if (cmp_in6_addr(&s.addr.ipv6.src, &rhs.s.addr.ipv6.src) &&
      cmp_in6_addr(&s.addr.ipv6.dst, &rhs.s.addr.ipv6.dst)) {
    if (__builtin_expect(s.protocol == IPPROTO_ICMP, false)) {
      if (s.si.icmp_tp == rhs.s.si.icmp_tp &&
          s.di.icmp_cd == rhs.s.di.icmp_cd) {
        direction = false;
        return true;
      }
    } else if (s.si.sport == rhs.s.si.sport &&
               s.di.dport == rhs.s.di.dport) {
      direction = false;
      return true;
    }
  }
  if (cmp_in6_addr(&s.addr.ipv6.src, &rhs.s.addr.ipv6.dst) &&
      cmp_in6_addr(&s.addr.ipv6.dst, &rhs.s.addr.ipv6.src)) {
    if (__builtin_expect(s.protocol == IPPROTO_ICMP, false)) {
        if (s.si.icmp_tp == rhs.s.si.icmp_tp &&
            s.di.icmp_cd == rhs.s.di.icmp_cd) {
          direction = true;
          return true;
      }
    } else if (s.si.sport == rhs.s.di.dport &&
               s.di.dport == rhs.s.si.sport) {
      direction = true;
      return true;
    }
  }
  return false;
}

void Session::setMatcher(uint32_t matcher_idx_) {
  matcher_idx = matcher_idx_;
}

uint32_t Session::getMatcher() const {
  return matcher_idx;
}

bool SessionTable::find(Session &s) {
  std::cout << "find session s" << "\n";
  auto its = sessionTable.equal_range(s.getHashval());
  auto it = its.first;
  for (; it != its.second; ++it) {
    if ((*it).second == s) {
      s = (*it).second;
      std::cout << "found " << (*it).second.getDirection() << "\n";
      return true;
    }
  }
  if (it == its.second) {
    s.setMatcher(SessionTable::nextMatcher());
    sessionTable.insert(std::make_pair(s.getHashval(), s));
    std::cout << "not found, insert\n";
  }
  return false;
}

uint32_t SessionTable::nextMatcher() {
  auto t = nmatchers;
  nmatchers += 2;
  return t;
}

uint32_t SessionTable::nmatchers = 0;
