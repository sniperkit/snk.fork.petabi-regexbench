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

#include <boost/program_options.hpp>

#include "BackgroundJobs.h"
#include "BoostEngine.h"
#include "CPPEngine.h"
#ifdef HAVE_HYPERSCAN
#include "HyperscanEngine.h"
#endif
#ifdef HAVE_PCRE2
#include "PCRE2Engine.h"
#endif
#include "PcapSource.h"
#ifdef HAVE_RE2
#include "RE2Engine.h"
#endif
#ifdef HAVE_REMATCH
#include "REmatchEngine.h"
#endif
#include "Logger.h"
#include "Rule.h"
#include "regexbench.h"

namespace po = boost::program_options;

template <typename Derived, typename Base, typename Del>
std::unique_ptr<Derived, Del>
static_unique_ptr_cast(std::unique_ptr<Base, Del>&& p)
{
  auto d = static_cast<Derived*>(p.release());
  return std::unique_ptr<Derived, Del>(d, std::move(p.get_deleter()));
}

static bool endsWith(const std::string&, const char*);
static EngineType getEngineType(const std::string& engine);

int regexbench::exec(Arguments& args, realtimeFunc func, void* p)
{
  try {
    std::string prefix;
    size_t nsessions = 0;
    regexbench::PcapSource pcap(args.pcap_file);
    auto match_info = buildMatchMeta(pcap, nsessions);

    struct rusage compileBegin, compileEnd;
    getrusage(RUSAGE_SELF, &compileBegin);

    auto engine = regexbench::loadEngine(args, prefix, nsessions);

    getrusage(RUSAGE_SELF, &compileEnd);
    args.compile_time =
        compileReport(compileBegin, compileEnd, pcap, args.quiet);

    // set up background jobs
    using BGJ = regexbench::BackgroundJobs;
    BGJ bgj(args.update_pipe, engine.get(), args.rule_file, args.compile_test);
    regexbench::setAffinity(args.cores[0], "background");
    bgj.start(); // launch background jobs (to actually run or not will be
                 // determined inside class instance)

    std::vector<regexbench::MatchResult> results =
        match(*engine, pcap, args.repeat, args.cores, match_info, args.log_file,
              func, p);

    report(prefix, pcap, args, results);

    bgj.stop();
  } catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

std::unique_ptr<regexbench::Engine>
regexbench::loadEngine(Arguments& args, std::string& prefix, size_t nsessions)
{
  std::unique_ptr<regexbench::Engine> engine;

  switch (args.engine) {
  case EngineType::boost:
    prefix = "boost";
    engine = std::make_unique<regexbench::BoostEngine>();
    engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    break;
  case EngineType::std_regex:
    engine = std::make_unique<regexbench::CPPEngine>();
    engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    break;
#ifdef HAVE_HYPERSCAN
  case EngineType::hyperscan:
    prefix = "hyperscan";
    if (args.rematch_session) {
      engine = std::make_unique<regexbench::HyperscanEngineStream>();
      engine->init(nsessions);
    } else {
      engine = std::make_unique<regexbench::HyperscanEngine>();
    }
    engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    break;
#endif
#ifdef HAVE_PCRE2
  case EngineType::pcre2:
    prefix = "pcre2";
    engine = std::make_unique<regexbench::PCRE2Engine>();
    engine->init(args.pcre2_concat);
    engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    break;
  case EngineType::pcre2_jit:
    engine = std::make_unique<regexbench::PCRE2JITEngine>();
    engine->init(args.pcre2_concat);
    engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    break;
#endif
#ifdef HAVE_RE2
  case EngineType::re2:
    prefix = "re2";
    engine = std::make_unique<regexbench::RE2Engine>();
    engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    break;
#endif
#ifdef HAVE_REMATCH
  case EngineType::rematch:
    prefix = "rematch";
    if (args.rematch_session) {
#ifdef WITH_SESSION
      engine = std::make_unique<regexbench::REmatchAutomataEngineSession>(
          args.nmatch);
      engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
#endif
    } else if (endsWith(args.rule_file, ".nfa")) {
      engine = std::make_unique<regexbench::REmatchAutomataEngine>(args.nmatch);
      engine->load(args.rule_file, args.num_threads);
    } else if (endsWith(args.rule_file, ".so")) {
      engine = std::make_unique<regexbench::REmatchSOEngine>();
      engine->load(args.rule_file, args.num_threads);
    } else {
      engine = std::make_unique<regexbench::REmatchAutomataEngine>(args.nmatch,
                                                                   args.reduce);
      engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    }
    engine->init(nsessions);
    break;
  case EngineType::rematch2:
    prefix = "rematch2";
    if (endsWith(args.rule_file, ".nfa")) {
      engine =
          std::make_unique<regexbench::REmatch2AutomataEngine>(args.nmatch);
      engine->load(args.rule_file, args.num_threads);
    } else {
      engine = std::make_unique<regexbench::REmatch2AutomataEngine>(args.nmatch,
                                                                    args.reduce
#ifdef USE_TURBO
                                                                    ,
                                                                    args.turbo
#endif
                                                                    );
      engine->compile(regexbench::loadRules(args.rule_file), args.num_threads);
    }
    break;
#endif
  case EngineType::unknown:
    break;
  }

  return engine;
}

bool endsWith(const std::string& obj, const char* end)
{
  auto r = obj.rfind(end);
  if ((r != std::string::npos) && (r == obj.size() - std::strlen(end)))
    return true;
  return false;
}

static std::vector<size_t> setup_affinity(size_t num, const std::string& arg)
{
  auto ncpus = std::thread::hardware_concurrency();

  // num : user specified number of threads of matchers
  //   (main thread is not included here)
  // arg : user specified description of core assignment
  //   (comma separated decimals w/o space in between)

  num += 1;    // main thread included
  int inc = 1; // automatic increase value

  // firstly check if there's trailing ":[decimal's]"
  auto pos = arg.find(":");
  if (pos != std::string::npos) {
    std::string incStr = arg.substr(pos + 1);
    if (incStr.empty())
      inc = 0;
    try {
      inc = stoi(incStr);
    } catch (const std::exception&) {
    }
  }

  std::string csv = arg.substr(0, pos);

  // parse comma separated input
  std::replace(csv.begin(), csv.end(), ',', ' ');
  std::istringstream is(csv);

  std::vector<size_t> cores(num); // to return
  int maxCore = static_cast<int>(ncpus - 1);
  try {
    std::istream_iterator<int> iter = std::istream_iterator<int>(is);
    int last = 0;
    std::generate(cores.begin(), cores.end(), [&iter, &last, inc, maxCore]() {
      int core = 0;
      if (iter != std::istream_iterator<int>()) {
        core = std::min(std::max(*iter, 0), maxCore);
        ++iter;
      } else
        core = std::min(std::max(last + inc, 0), maxCore);
      last = core;
      return static_cast<size_t>(core);
    });
  } catch (const std::exception&) {
    // some formatting error
    std::cerr << "User provided affinity assignment format error" << std::endl;
    // go with default assignment scheme
    for (int i = 0; i < static_cast<int>(num); ++i)
      cores[static_cast<size_t>(i)] =
          static_cast<size_t>((i > maxCore) ? maxCore : i);
  }
  return cores;
}

EngineType getEngineType(const std::string& engine)
{
  if (engine == "boost")
    return EngineType::boost;
  else if (engine == "cpp")
    return EngineType::std_regex;
#ifdef HAVE_HYPERSCAN
  else if (engine == "hyperscan")
    return EngineType::hyperscan;
#endif
#ifdef HAVE_PCRE2
  else if (engine == "pcre2")
    return EngineType::pcre2;
  else if (engine == "pcre2jit")
    return EngineType::pcre2_jit;
#endif
#ifdef HAVE_RE2
  else if (engine == "re2")
    return EngineType::re2;
#endif
#ifdef HAVE_REMATCH
  else if (engine == "rematch")
    return EngineType::rematch;
  else if (engine == "rematch2")
    return EngineType::rematch2;
#endif
  return EngineType::unknown;
}

Arguments regexbench::parse_options(int argc, const char* argv[])
{
  Arguments args;
  std::string engine;
  std::string prefix;
  std::string affinity;

  po::options_description posargs;
  posargs.add_options()("rule_file", po::value<std::string>(&args.rule_file),
                        "Rule (regular expression) file name");
  posargs.add_options()("pcap_file", po::value<std::string>(&args.pcap_file),
                        "pcap file name");
  po::positional_options_description positions;
  positions.add("rule_file", 1).add("pcap_file", 1);

  po::options_description optargs("Options");
  optargs.add_options()("help,h", "Print usage information.");
  optargs.add_options()(
      "engine,e", po::value<std::string>(&engine)->default_value("hyperscan"),
      "Matching engine to run.");
  optargs.add_options()("repeat,r",
                        po::value<int32_t>(&args.repeat)->default_value(1),
                        "Repeat pcap multiple times.");
  optargs.add_options()(
      "concat,c", po::value<uint32_t>(&args.pcre2_concat)->default_value(0),
      "Concatenate PCRE2 rules.");
  optargs.add_options()(
      "session,s", po::value<uint32_t>(&args.rematch_session)->default_value(0),
      "Rematch session mode.");
  optargs.add_options()("prefix,p",
                        po::value<std::string>(&prefix)->default_value(""),
                        "Prefix to output json file name");
  optargs.add_options()(
      "output,o", po::value<std::string>(&args.output_file)->default_value(""),
      "Output JSON file.");
  optargs.add_options()(
      "detail,d", po::value<std::string>(&args.detail_file)->default_value(""),
      "Save detailed match result to a json file");
  optargs.add_options()(
      "logfile,l", po::value<std::string>(&args.log_file)->default_value(""),
      "Log file.");
  optargs.add_options()(
      "threads,n", po::value<uint32_t>(&args.num_threads)->default_value(1),
      "Number of threads.");
  optargs.add_options()("affinity,a",
                        po::value<std::string>(&affinity)->default_value("0"),
                        "Core affinity assignment (starting from main thread)");
  optargs.add_options()("reduce,R",
                        po::value<bool>(&args.reduce)->default_value(false),
                        "Use REduce with REmatch, default is false");
  optargs.add_options()(
      "compile,t", po::value<uint32_t>(&args.compile_test)->default_value(0),
      "Compile test");
  optargs.add_options()(
      "update,u", po::value<std::string>(&args.update_pipe)->default_value(""),
      "Pipe for signaling online update");
#ifdef USE_TURBO
  optargs.add_options()("turbo", "Turbo processing mode for rematch2");
#endif
  optargs.add_options()("match_num,m",
                        po::value<uint32_t>(&args.nmatch)->default_value(0),
                        "Match number");
  optargs.add_options()("quiet,q", "Quiet mode, default is false");
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
    std::cout << posargs << "\n" << optargs << "\n";
    std::exit(EXIT_SUCCESS);
  }

#ifdef USE_TURBO
  if (vm.count("turbo"))
    args.turbo = true;
#endif
  if (vm.count("quiet"))
    args.quiet = true;

  args.engine = getEngineType(engine);
  if (args.engine == EngineType::unknown) {
    std::cerr << "unknown engine: " << engine << std::endl;
    std::exit(EXIT_FAILURE);
  }
  if (args.repeat <= 0) {
    std::cerr << "invalid repeat value: " << args.repeat << std::endl;
    std::exit(EXIT_FAILURE);
  }
  if (args.num_threads < 1) {
    std::cerr << "invalid number of threads: " << args.num_threads << std::endl;
    std::cerr << " (should be >= 1 .. overriding it to 1" << std::endl;
    args.num_threads = 1;
  }

  if (!args.quiet) {
    std::cout << "number of threads : " << args.num_threads << std::endl;
    args.cores = setup_affinity(args.num_threads, affinity);
    std::cout << "affinity setup is ..." << std::endl;
    for (auto core : args.cores)
      std::cout << " " << core;
    std::cout << std::endl;
  } else
    args.cores = setup_affinity(args.num_threads, affinity);

#ifndef WITH_SESSION
  if ((engine == "rematch" || engine == "rematch2") && args.rematch_session) {
    std::cerr << "not supporting session mode for now" << std::endl;
    args.rematch_session = 0;
  }
#endif

  if (args.output_file.empty()) {
    std::string name = prefix;
    if (!name.empty())
      name += "-";
    name += engine + "-";
    auto basename = args.rule_file;
    auto pos = basename.find_last_of("/\\");
    basename = basename.substr((pos == std::string::npos) ? 0 : pos + 1);
    name += basename + "-"; // rule
    basename = args.pcap_file;
    pos = basename.find_last_of("/\\");
    basename = basename.substr((pos == std::string::npos) ? 0 : pos + 3);
    name += basename + "-";                               // pcap
    name += "N" + std::to_string(args.num_threads) + "-"; // num threads
    name += "R" + std::to_string(args.repeat) + ".json";  // repeat

    args.output_file = name;
    if (!args.quiet) {
      std::cout << "Output file name is " << args.output_file << std::endl;
    }
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

Arguments regexbench::init(const std::string& rule_file,
                           const std::string& pcap_file,
                           const std::string& output_file,
                           const std::string& engine, uint32_t nthreads,
                           const std::string& affinity, int32_t repeat)
{
  Arguments args;

  args.engine = getEngineType(engine);
  if (args.engine == EngineType::unknown) {
    throw std::invalid_argument("unknown engine " + engine);
  }

  args.rule_file = rule_file;
  args.pcap_file = pcap_file;
  args.output_file = output_file;
  args.repeat = repeat;
  args.pcre2_concat = 0;
  args.rematch_session = 0;
  args.compile_test = 0;
  args.num_threads = nthreads;
  args.update_pipe = "";
  args.log_file = "";
  args.quiet = true;
  args.nmatch = 0;
  args.cores = setup_affinity(nthreads, affinity);

  return args;
}
