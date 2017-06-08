#include "regexbench.h"

using namespace regexbench;

int main(int argc, const char* argv[])
{
  try {
    auto args = regexbench::parse_options(argc, argv);
    if (args.quiet)
      return regexbench::exec(args);
    return regexbench::exec(args, regexbench::realtimeReport);
  } catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
