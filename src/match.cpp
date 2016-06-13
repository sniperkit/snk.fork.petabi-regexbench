#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <fstream>
#include <iostream>

#include "Engine.h"
#include "PcapSource.h"
#include "regexbench.h"
#include "Session.h"

using namespace regexbench;

uint32_t regexbench::getPLOffset(const std::string &packet) {
  uint16_t offset = 0;
  uint16_t ether_type =
      ntohs(reinterpret_cast<const ether_header *>(packet.data())->ether_type);
  if (ether_type == ETHERTYPE_VLAN) {
    offset = 4;
    ether_type =
        ntohs(reinterpret_cast<const ether_header *>(packet.data() + offset)
                  ->ether_type);
  }
  switch (ether_type) {
  case ETHERTYPE_IP: {
    offset += sizeof(ether_header);
    const ip *ih = reinterpret_cast<const ip *>(packet.data() + offset);
    offset += ih->ip_hl << 2;
    switch (ih->ip_p) {
    case IPPROTO_TCP:
      offset += reinterpret_cast<const tcphdr *>(packet.data() + offset)->th_off
                << 2;
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
  } break;
  case ETHERTYPE_IPV6: {
    offset += sizeof(ether_header) + sizeof(ip6_hdr);
    const ip6_hdr *ih6 =
        reinterpret_cast<const ip6_hdr *>(packet.data() + offset);
    switch (ih6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
    case IPPROTO_TCP:
      offset += reinterpret_cast<const tcphdr *>(packet.data() + offset)->th_off
                << 2;
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
  } break;
  default:
    break;
  }
  return offset;
}

std::vector<MatchMeta> regexbench::buildMatchMeta(const PcapSource &src,
                                                  size_t &nsessions) {
  std::vector<MatchMeta> matcher_info;
  SessionTable sessionTable;
  for (const auto &pkt : src) {
    auto offset = getPLOffset(pkt);
    size_t sid = 0;
    Session s(pkt.data());
    sessionTable.find(s, sid);

    matcher_info.emplace_back(sid, offset, pkt.size() - offset);
  }
  nsessions = sessionTable.getSessionNum();
  return matcher_info;
}

MatchResult regexbench::sessionMatch(Engine &engine, const PcapSource &src,
                              long repeat, const std::vector<MatchMeta> &meta) {
  struct rusage begin, end;
  MatchResult result;
  getrusage(RUSAGE_SELF, &begin);
  for (long i = 0; i < repeat; ++i) {
    for (size_t j = 0; j < src.getNumberOfPackets(); j++) {
      auto matches = engine.match(src[j].data() + meta[j].oft, meta[j].len, meta[j].sid);

      if (matches) {
        result.nmatches += matches;
        result.nmatched_pkts++;
      }
    }
  }
  getrusage(RUSAGE_SELF, &end);
  timersub(&(end.ru_utime), &(begin.ru_utime), &result.udiff);
  timersub(&(end.ru_stime), &(begin.ru_stime), &result.sdiff);
  return result;
}

MatchResult regexbench::match(Engine &engine, const PcapSource &src,
                              long repeat, const std::vector<MatchMeta> &meta) {
  struct rusage begin, end;
  MatchResult result;
  getrusage(RUSAGE_SELF, &begin);
  for (long i = 0; i < repeat; ++i) {
    for (size_t j = 0; j < src.getNumberOfPackets(); j++) {
      auto matches = engine.match(src[j].data() + meta[j].oft, meta[j].len, meta[j].sid);

      if (matches) {
        result.nmatches += matches;
        result.nmatched_pkts++;
      }
    }
  }
  getrusage(RUSAGE_SELF, &end);
  timersub(&(end.ru_utime), &(begin.ru_utime), &result.udiff);
  timersub(&(end.ru_stime), &(begin.ru_stime), &result.sdiff);
  return result;
}

std::vector<regexbench::Rule> regexbench::loadRules(const std::string &filename) {
  std::ifstream ruleifs(filename);
  if (!ruleifs) {
    std::cerr << "cannot open rule file: " << filename << std::endl;
    std::exit(EXIT_FAILURE);
  }
  return regexbench::loadRules(ruleifs);
}
