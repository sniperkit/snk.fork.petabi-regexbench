#include <stdexcept>

#include <rematch/compile.h>
#include <rematch/execute.h>
#include <rematch/rematch.h>

#include "REmatchEngine.h"

using namespace regexbench;

REmatchEngine::REmatchEngine()
    : context(nullptr), txtbl(nullptr) {
}

REmatchEngine::~REmatchEngine() {
  if (context)
    destroy_matchctx(context);
  if (txtbl)
    mregfree(txtbl);
}

void REmatchEngine::compile(const std::vector<Rule> &rules) {
  std::vector<const char *> exps;
  std::vector<unsigned> mods;
  std::vector<unsigned> ids;
  for (const auto &rule : rules) {
    exps.push_back(rule.getRegexp().data());
    ids.push_back(static_cast<unsigned>(rule.getID()));
    mods.push_back(rule.getPCRE2Options());
  }
  txtbl = rematch_compile(ids.data(), exps.data(), mods.data(), ids.size());
  context = create_matchctx(txtbl->nstates);
  if (context == nullptr)
    throw std::bad_alloc();
}

bool REmatchEngine::match(const char *data, size_t len) {
  return rematch_execute(txtbl, data, len, context) != nullptr;
}

void REmatchEngine::load(const std::string &NFAFile) {
  txtbl = rematchload(NFAFile.c_str());
  if (txtbl == nullptr) {
    throw std::runtime_error("cannot load nfa\n");
  }
  context = create_matchctx(txtbl->nstates);
  if (context == nullptr)
    throw std::bad_alloc();
}
