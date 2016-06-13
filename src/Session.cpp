#include "Session.h"

#include <string>

using namespace regexbench;

static uint8_t RSK[40] = {0x6d, 0xa5, 0x6d, 0xa4, 0x6d, 0xa5, 0x6d, 0xa4,
                          0x6d, 0xa5, 0x6d, 0xa5, 0x6d, 0xa5, 0x6d, 0xa4,
                          0x6d, 0xa5, 0x6d, 0xa4, 0x6d, 0xa5, 0x6d, 0xa4,
                          0x6d, 0xa5, 0x6d, 0xa5, 0x6d, 0xa5, 0x6d, 0xa4,
                          0x6d, 0xa5, 0x6d, 0xa4, 0x6d, 0xa5, 0x6d, 0xa4};

enum HashField : size_t {
  RSS_FIELD_IPV4_TCP_UDP = 0x0,
  RSS_FIELD_IPV4 = 0x1,
  RSS_FIELD_IPV6_TCP_UDP = 0x2,
  RSS_FIELD_IPV6 = 0x3
};

constexpr struct HashFieldInfo {
  uint32_t offset;
  uint32_t n;
} HashFieldInfo[] = {{12, 12}, {12, 8}, {8, 36}, {8, 32}};

/**
 * Build symmetric hash key from raw pkt. Please note the choice of hash field
 * (IPv4, IPv6 with/without TCP header) has to be consistent with NIC drivers
 * in order to get the same hash value.
 */
inline uint32_t Session::computeRSSHash(const uint8_t *pkt) {
  const struct ether_header *hd =
      reinterpret_cast<const struct ether_header *>(pkt);
  size_t type = 0;
  uint8_t ipproto = 0;

  if (ntohs(hd->ether_type) == ETHERTYPE_IP) {
    const struct ip *ip =
        reinterpret_cast<const struct ip *>(pkt + sizeof(struct ether_header));
    ipproto = ip->ip_p;
    type = (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)
               ? RSS_FIELD_IPV4_TCP_UDP
               : RSS_FIELD_IPV4;

  } else if (ntohs(hd->ether_type) == ETHERTYPE_IPV6) {
    const struct ip6_hdr *ip6 = reinterpret_cast<const struct ip6_hdr *>(
        pkt + sizeof(struct ether_header));
    ipproto = ip6->ip6_nxt;
    type = (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)
               ? RSS_FIELD_IPV6_TCP_UDP
               : RSS_FIELD_IPV6;

  } else
    return 0;

  /*
   * The input one single byte array is pkt itself, we avoid the endianness
   * issue and perserve the byte order also avoid any copies. The only thing
   * we need to do is specify the offset where source ip starts. Then we have
   * the input array consisting of src_ip, dst_ip, src_port, dst_port.
   */

  unsigned long offset =
      HashFieldInfo[type].offset + sizeof(struct ether_header);
  uint32_t hv = 0;
  uint32_t t =
      static_cast<uint32_t>(RSK[0] << 24 | RSK[1] << 16 | RSK[2] << 8 | RSK[3]);

  for (size_t i = 0; i < HashFieldInfo[type].n; i++) {
    for (size_t j = 0; j < 8; j++) {
      if (pkt[offset + i] & (1 << (7 - j)))
        hv ^= t;

      t <<= 1;
      if (RSK[i + 4] & (1 << (7 - j))) {
        t |= 1;
      }
    }
  }
  return hv;
}

Session::Session(const char *pkt) : matcher_idx(0) {
  hashval = computeRSSHash(reinterpret_cast<const uint8_t *>(pkt));

  ether_type = ntohs(reinterpret_cast<const ether_header *>(pkt)->ether_type);
  uint16_t size_iphdr = 0;
  if (ether_type == ETHERTYPE_IPV6) {
    protocol =
        reinterpret_cast<const ip6_hdr *>(pkt + ETHER_HDR_LEN)->ip6_nxt;

    size_iphdr = 40;
    memcpy(&addr.ipv6.src, EXT_SIP6(pkt), 16);
    memcpy(&addr.ipv6.dst, EXT_DIP6(pkt), 16);
  } else if (ether_type == ETHERTYPE_IP) {
    auto ih = reinterpret_cast<const ip *>(pkt + ETHER_HDR_LEN);
    protocol = ih->ip_p;
    size_iphdr = static_cast<uint16_t>(ih->ip_hl << 2);
    addr.ipv4.src.s_addr = EXT_SIP(pkt);
    addr.ipv4.dst.s_addr = EXT_DIP(pkt);
  }

  if (protocol == IPPROTO_ICMP) {
    si.icmp_tp = EXT_ICMP_TP(pkt, size_iphdr);
    di.icmp_cd = EXT_ICMP_CD(pkt, size_iphdr);
  } else {
    si.sport = EXT_SPORT(pkt, size_iphdr);
    di.dport = EXT_DPORT(pkt, size_iphdr);
  }

  // pl_off = getPLOff(protocol);
}

bool Session::operator==(const Session &rhs) {
  if (ether_type != rhs.ether_type || protocol != rhs.protocol)
    return false;
  if (ether_type == ETHERTYPE_IP) {
    if (addr.ipv4.src.s_addr == rhs.addr.ipv4.src.s_addr &&
        addr.ipv4.dst.s_addr == rhs.addr.ipv4.dst.s_addr) {
      if (__builtin_expect(protocol == IPPROTO_ICMP, false)) {
        if (si.icmp_tp == rhs.si.icmp_tp &&
            di.icmp_cd == rhs.di.icmp_cd) {
          direction = false;
          return true;
        }
      } else if (si.sport == rhs.si.sport && di.dport == rhs.di.dport) {
        direction = false;
        return true;
      }
    }
    if (addr.ipv4.src.s_addr == rhs.addr.ipv4.dst.s_addr &&
        addr.ipv4.dst.s_addr == rhs.addr.ipv4.src.s_addr) {
      if (__builtin_expect(protocol == IPPROTO_ICMP, false)) {
        if (si.icmp_tp == rhs.si.icmp_tp &&
            di.icmp_cd == rhs.di.icmp_cd) {
          direction = true;
          return true;
        }
      } else if (si.sport == rhs.di.dport && di.dport == rhs.si.sport) {
        direction = true;
        return true;
      }
    }
    return false;
  }

  // IPv6
  if (cmp_in6_addr(&addr.ipv6.src, &rhs.addr.ipv6.src) &&
      cmp_in6_addr(&addr.ipv6.dst, &rhs.addr.ipv6.dst)) {
    if (__builtin_expect(protocol == IPPROTO_ICMP, false)) {
      if (si.icmp_tp == rhs.si.icmp_tp &&
          di.icmp_cd == rhs.di.icmp_cd) {
        direction = false;
        return true;
      }
    } else if (si.sport == rhs.si.sport && di.dport == rhs.di.dport) {
      direction = false;
      return true;
    }
  }
  if (cmp_in6_addr(&addr.ipv6.src, &rhs.addr.ipv6.dst) &&
      cmp_in6_addr(&addr.ipv6.dst, &rhs.addr.ipv6.src)) {
    if (__builtin_expect(protocol == IPPROTO_ICMP, false)) {
      if (si.icmp_tp == rhs.si.icmp_tp &&
          di.icmp_cd == rhs.di.icmp_cd) {
        direction = true;
        return true;
      }
    } else if (si.sport == rhs.di.dport && di.dport == rhs.si.sport) {
      direction = true;
      return true;
    }
  }
  return false;
}

bool SessionTable::find(Session &s, size_t &sid) {
  auto its = sessionTable.equal_range(s.getHashval());
  auto it = its.first;
  for (; it != its.second; ++it) {
    if (s == (*it).second) {
      sid = s.getSession() * 2 + (s.getDirection() ? 1 : 0);
      return true;
    }
  }
  if (it == its.second) {
    s.setSession(nsessions++);
    sessionTable.insert(std::make_pair(s.getHashval(), s));
    sid = s.getSession() * 2;
  }
  return false;
}

uint32_t SessionTable::nsessions = 0;
