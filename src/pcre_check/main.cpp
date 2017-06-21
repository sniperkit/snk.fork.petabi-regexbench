#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <boost/program_options.hpp>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <rematch/compile.h>
#include <rematch/execute.h>
#include <rematch/rematch.h>

#include "../Rule.h"
//#include "CheckerShell.h" // TODO
#include "PcreChecker.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;

using regexbench::Rule;

namespace po = boost::program_options;

static void usage(const po::options_description& pos,
                  const po::options_description& opt)
{
  cout << "Usage: pcre_checker <mode> options..." << endl;
  cout << pos << endl << opt << endl;
}

static int runShell();

int main(int argc, char** argv)
{
  string mode;
  string dbFile;
  string jsonIn;
  string jsonOut;
  po::options_description posargs;
  posargs.add_options()(
      "mode", po::value<string>(&mode),
      "mode to execute : 'shell' or 'command' (default to 'command')");
  po::positional_options_description positions;
  positions.add("mode", 1);
  po::options_description optargs("Options");
  optargs.add_options()("help,h", "Print usage information.");
  optargs.add_options()("db,d", po::value<string>(&dbFile),
                        "sqlite3 db file name to use");
  optargs.add_options()("input,i", po::value<string>(&jsonIn),
                        "json input file");
  optargs.add_options()("output,o", po::value<string>(&jsonOut),
                        "write db content to json output file");
  optargs.add_options()("setup,s", "setup db from json input");
  optargs.add_options()("update,u",
                        "update the result to db");
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
    usage(posargs, optargs);
    std::exit(EXIT_SUCCESS);
  }

  if (vm.count("mode")) {
    if (std::string("shell").find(mode) == 0) {
      cout << "Entering shell mode" << endl;
      return runShell();
    } else if (std::string("command").find(mode) != 0) {
      cout << "Unknown mode '" << mode << "' specified!!" << endl;
      usage(posargs, optargs);
      std::exit(EXIT_SUCCESS);
    }
  }

  //
  // From this point on we are gonna do works related to command mode
  //
  bool setup = vm.count("setup") ? true : false;
  bool update = vm.count("update") ? true : false;

  try {
    PcreChecker chk(dbFile); // if debugging is needed,
                             // set debug true
    if (setup)
      chk.setupDb(jsonIn);
    if (update)
      chk.checkDb();
    if (!jsonOut.empty())
      chk.writeJson(jsonOut);
  } catch (const std::exception& e) {
    cerr << e.what() << endl;
    return -1;
  }
  return 0;
}

int runShell()
{
  /*
  try {
    CheckerShell shell;
    shell.initialize();
    shell.run();
  } catch (const std::exception& ex) {
    cerr << ex.what() << endl;
    return -1;
  }
  */ // TODO

  return 0;
}
