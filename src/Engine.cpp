#include "Engine.h"

using namespace regexbench;

Engine::~Engine() {}

int Engine::onMatchCallback(unsigned id, unsigned long long from,
                            unsigned long long to, unsigned flags, void* ctx)
{
  auto res = static_cast<result_type*>(ctx);
  ++(res->count);
  if (res->resMap)
    (*res->resMap)[id].insert(
        std::make_pair(static_cast<size_t>(from), static_cast<size_t>(to)));
  if (res->eng->nmatch > 0 && res->count >= res->eng->nmatch)
    return 1;
  return 0;
}
