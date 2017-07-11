#include "config.h"

#include <sys/resource.h>
#include <sys/time.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <boost/format.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "Logger.h"
#include "PcapSource.h"
#include "Rule.h"
#include "regexbench.h"

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

using namespace regexbench;

std::string regexbench::compileReport(const struct rusage& compileBegin,
                                      const struct rusage& compileEnd,
                                      const PcapSource& pcap, bool quiet)
{
  struct timeval compileUdiff, compileSdiff;
  timersub(&(compileEnd.ru_utime), &(compileBegin.ru_utime), &compileUdiff);
  timersub(&(compileEnd.ru_stime), &(compileBegin.ru_stime), &compileSdiff);
  auto compileTime = (compileUdiff.tv_sec + compileSdiff.tv_sec +
                      (compileUdiff.tv_usec + compileSdiff.tv_usec) * 1e-6);
  if (!quiet) {
    std::cout << std::endl;
    std::cout << "Compile time : " << compileTime << std::endl << std::endl;
    std::cout << "Pcap TotalBytes : " << pcap.getNumberOfBytes() << std::endl;
    std::cout << "Pcap TotalPackets : " << pcap.getNumberOfPackets()
              << std::endl
              << std::endl;
  }

  return std::to_string(compileTime);
}

void regexbench::report(std::string& prefix, const PcapSource& pcap,
                        const Arguments& args,
                        const std::vector<MatchResult>& results)
{
  std::string reportFields[]{"TotalMatches", "TotalMatchedPackets",
                             "UserTime",     "SystemTime",
                             "TotalTime",    "Mbps",
                             "Mpps",         "MaximumMemoryUsed(MB)"};

  auto coreIter = args.cores.cbegin();

  coreIter++; // get rid of main thread

  boost::property_tree::ptree pt;
  prefix = prefix + ".";
  pt.put(prefix + "Logging", args.log_file.empty() ? "Off" : "On");
  pt.put(prefix + "Repeat", args.repeat);
  std::string rulePrefix = prefix + "Rule.";
  pt.put(rulePrefix + "File", args.rule_file);
  pt.put(rulePrefix + "CompileTime", args.compile_time);
  if (args.reduce && (args.engine == EngineType::rematch ||
                      args.engine == EngineType::rematch2))
    pt.put(rulePrefix + "Reduce", "On");
  std::string pcapPrefix = prefix + "Pcap.";
  pt.put(pcapPrefix + "File", args.pcap_file);
  pt.put(pcapPrefix + "TotalBytes", pcap.getNumberOfBytes());
  pt.put(pcapPrefix + "TotalPackets", pcap.getNumberOfPackets());
  pt.put(prefix + "NumThreads", args.num_threads);
  size_t coreInd = 0;
  std::string threadsPrefix = prefix + "Threads.";
  for (const auto& result : results) {
    std::stringstream ss;
    ss << "Thread" << coreInd++ << ".";
    std::string corePrefix = threadsPrefix + ss.str();
    pt.put(corePrefix + "Core", *coreIter++);
    pt.put(corePrefix + "TotalMatches", result.cur.nmatches);
    pt.put(corePrefix + "TotalMatchedPackets", result.cur.nmatched_pkts);
    ss.str("");
    auto t = result.udiff.tv_sec + result.udiff.tv_usec * 1e-6;
    ss << t;
    pt.put(corePrefix + "UserTime", ss.str());
    ss.str("");
    t = result.sdiff.tv_sec + result.sdiff.tv_usec * 1e-6;
    ss << t;
    pt.put(corePrefix + "SystemTime", ss.str());
    ss.str("");
    struct timeval total;
    timeradd(&result.udiff, &result.sdiff, &total);
    t = total.tv_sec + total.tv_usec * 1e-6;
    ss << t;
    pt.put(corePrefix + "TotalTime", ss.str());
    ss.str("");
    ss << std::fixed << std::setprecision(6)
       << (static_cast<double>(pcap.getNumberOfBytes() *
                               static_cast<unsigned long>(args.repeat)) /
           (total.tv_sec + total.tv_usec * 1e-6) / 1000000 * 8);
    pt.put(corePrefix + "Mbps", ss.str());

    ss.str("");
    ss << std::fixed << std::setprecision(6)
       << (static_cast<double>(pcap.getNumberOfPackets() *
                               static_cast<unsigned long>(args.repeat)) /
           (total.tv_sec + total.tv_usec * 1e-6) / 1000000);
    pt.put(corePrefix + "Mpps", ss.str());
    struct rusage stat;
    getrusage(RUSAGE_SELF, &stat);
    pt.put(corePrefix + "MaximumMemoryUsed(MB)", stat.ru_maxrss / 1000);

    if (!args.quiet) {
      std::cout << "\n";
      for (const auto& it : reportFields) {
        std::cout << it << " : " << pt.get<std::string>(corePrefix + it)
                  << "\n";
      }
      std::cout << std::endl;
    }
  }

  std::ostringstream buf;
  write_json(buf, pt, true);
  std::ofstream outputFile(args.output_file, std::ios_base::trunc);
  outputFile << buf.str();

  if (!args.detail_file.empty() && !results.empty()) {
    const auto& pkt2RuleOffset = results[0].detail;
    boost::property_tree::ptree detailTree;

    for (const auto& pkt : pkt2RuleOffset) {
      std::string pktNo =
          std::string("pkt_") + std::to_string(pkt.first); // pkt no
      for (const auto& ruleOff : pkt.second) {
        std::string ruleNo =
            std::string("rule_") + std::to_string(ruleOff.first);
        boost::property_tree::ptree offsets;
        for (const auto& offPair : ruleOff.second) {
          boost::property_tree::ptree from, to, offset;
          from.put("", offPair.first);
          to.put("", offPair.second);
          offset.push_back(std::make_pair("", from));
          offset.push_back(std::make_pair("", to));
          offsets.push_back(std::make_pair("", offset));
        }
        detailTree.add_child(pktNo + "." + ruleNo, offsets);
      }
    }

    std::ostringstream detailBuf;
    write_json(detailBuf, detailTree, true);
    std::ofstream detailFile(args.detail_file, std::ios_base::trunc);
    detailFile << detailBuf.str();
  }
}

void regexbench::realtimeReport(const std::map<std::string, size_t>& m, void*)
{
  size_t sec = m.find("Sec")->second;
  bool isTotal = sec ? false : true;

  if (isTotal) {
    std::cout
        << "==============================================================="
        << "\n"
        << "TOTAL";
  } else
    std::cout << boost::format("#%03d ") % sec;

  for (const auto& it : m) {
    std::string format = " %s: %6d";

    if (it.first == "Sec")
      continue;
    else if (it.first == "Bytes")
      format = " %s: %10d";

    std::cout << boost::format(format) % it.first % it.second;
  }
  std::cout << std::endl;

  if (isTotal)
    std::cout << std::endl;
}
