#include "Engine.h"

using namespace regexbench;

Engine::~Engine() {}

// match callback with hyperscan compatible signature
// this will be used by rematch2 and hyperscan
int Engine::onMatchCallback(unsigned id, unsigned long long from,
                            unsigned long long to, unsigned /*flags*/,
                            void* ctx)
{
  auto res = static_cast<cb_ctxt_type*>(ctx);
  ++(res->count);
  if (res->resMap)
    (*res->resMap)[id].insert(
        std::make_pair(static_cast<size_t>(from), static_cast<size_t>(to)));
  if (res->eng->nmatch > 0 && res->count >= res->eng->nmatch)
    return 1;
  return 0;
}
