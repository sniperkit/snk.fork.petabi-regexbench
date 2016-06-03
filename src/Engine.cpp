#include <unordered_map>

#include "Engine.h"
#include "PcapSource.h"
#include "session.h"

using namespace regexbench;

Engine::~Engine() {}

void Engine::init(const PcapSource &src) {
  size_t nsessions = 0;
  SessionTable sessionTable;
  for (const auto &pkt : src) {
    Session s(pkt.data());
    auto result = sessionTable.find(s);
    if (result) {
      sessionIdx.push_back(s.getSessionIdx());
    } else {
      sessions.push_back(s);
      s.setSessionIdx(nsessions);
      sessionIdx.push_back(nsessions);
      nsessions++;
    }
  }
}
