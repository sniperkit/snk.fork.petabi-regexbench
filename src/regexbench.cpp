#include <iostream>
#include <string>

#include <boost/program_options.hpp>

namespace po = boost::program_options;

struct Arguments {
  std::string rule_file;
  std::string pcap_file;
};

static Arguments parse_options(int argc, const char *argv[]);

int main(int argc, const char *argv[]) {
  try {
    auto args = parse_options(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

Arguments parse_options(int argc, const char *argv[]) {
  Arguments args;

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
