#include "session.h"

#include <string>

using namespace regexbench;



Session::Session(const uint8_t *pkt) {
  s.hashval = pius::computeRSSHash(pkt);

  uint16_t ether_type = ntohs(reinterpret_cast<const ether_header *>(pkt)->ether_type);
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

  s.si.sport = EXT_SPORT(pkt, size_iphdr);
  s.di.dport = EXT_DPORT(pkt, size_iphdr);
  pl_off = getPLOff(s.protocol);
}

void SessionTable::find(const uint8_t *pkt) {
  uint32_t k = pius::computeRSSHash(pkt);
  auto its = sessionTable.equal_range(k);
  for (auto it = its.first; it != its.second; ++it) {
    ;
  }
}


// void SessionTable::insert(const uint8_t *pkt) {
//   uint32_t k = pkt_hash(pkt);
//   Session s(pkt);
//   sessionTable.insert(std::make_pair(k, s));
// }
