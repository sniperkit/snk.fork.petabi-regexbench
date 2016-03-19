#include <sys/time.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include <boost/program_options.hpp>

#include "HyperscanEngine.h"
#include "PcapSource.h"
#include "regexbench.h"
#include "REmatchEngine.h"
#include "Rule.h"

namespace po = boost::program_options;

enum EngineType : uint64_t {
  ENGINE_HYPERSCAN,
  ENGINE_REMATCH
};

struct Arguments {
  std::string rule_file;
  std::string pcap_file;
  EngineType engine;
};

static Arguments parse_options(int argc, const char *argv[]);

int main(int argc, const char *argv[]) {
  try {
    auto args = parse_options(argc, argv);
    std::unique_ptr<regexbench::Engine> engine;
    switch (args.engine) {
    case ENGINE_HYPERSCAN:
      engine = std::make_unique<regexbench::HyperscanEngine>();
      break;
    case ENGINE_REMATCH:
      engine = std::make_unique<regexbench::REmatchEngine>();
      break;
    }

    auto pos = args.rule_file.find_last_of(".nfa");
    if (pos != std::string::npos &&
        (pos + 1 == args.rule_file.size())) {
      if (!engine->load(args.rule_file))
        return EXIT_FAILURE;
    } else {
      std::ifstream ruleifs(args.rule_file);
      if (!ruleifs) {
        std::cerr << "cannot open rule file: " << args.rule_file << std::endl;
        return EXIT_FAILURE;
      }
      auto rules = regexbench::loadRules(ruleifs);
      ruleifs.close();
      engine->compile(rules);
    }
    regexbench::PcapSource pcap(args.pcap_file);
    auto result = match(*engine, pcap);
    std::cout << result.nmatches << " packets matched." << std::endl;
    std::cout << result.udiff.tv_sec << '.';
    std::cout.width(6);
    std::cout.fill('0');
    std::cout << result.udiff.tv_usec << "s user " << std::endl;
    std::cout << result.sdiff.tv_sec << '.';
    std::cout.width(6);
    std::cout.fill('0');
    std::cout << result.sdiff.tv_usec << "s system" << std::endl;
    struct timeval total;
    timeradd(&result.udiff, &result.sdiff, &total);
    std::cout
        << static_cast<double>(pcap.getNumberOfBytes()) /
        (total.tv_sec + total.tv_usec * 1e-6) / 1000000 * 8
        << " Mbps" << std::endl;
    std::cout
        << static_cast<double>(pcap.getNumberOfPackets()) /
        (total.tv_sec + total.tv_usec * 1e-6) / 1000000
        << " Mpps" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

Arguments parse_options(int argc, const char *argv[]) {
  Arguments args;
  std::string engine;

  po::options_description posargs;
  posargs.add_options()("rule_file",
                        po::value<std::string>(&args.rule_file),
                        "Rule (regular expression) file name");
  posargs.add_options()("pcap_file",
                        po::value<std::string>(&args.pcap_file),
                        "pcap file name");
  po::positional_options_description positions;
  positions.add("rule_file", 1).add("pcap_file", 1);

  po::options_description optargs("Options");
  optargs.add_options()("help,h", "Print usage information.");
  optargs.add_options()(
    "engine,e",
    po::value<std::string>(&engine)->default_value("hyperscan"),
    "Matching engine to run.");

  po::options_description cliargs;
  cliargs.add(posargs).add(optargs);
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv)
            .options(cliargs)
            .positional(positions)
            .run(),
            vm);
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << "Usage: regexbench <rule_file> <pcap_file>" << std::endl;
    std::exit(EXIT_SUCCESS);
  }
  if (engine == "hyperscan")
    args.engine = ENGINE_HYPERSCAN;
  else if (engine == "rematch")
    args.engine = ENGINE_REMATCH;
  else {
    std::cerr << "unknown engine: " << engine << std::endl;
    std::exit(EXIT_FAILURE);
  }

  if (!vm.count("rule_file")) {
    std::cerr << "error: no rule file" << std::endl;
    std::exit(EXIT_FAILURE);
  }
  if (!vm.count("pcap_file")) {
    std::cerr << "error: no pcap file" << std::endl;
    std::exit(EXIT_FAILURE);
  }
  return args;
}
