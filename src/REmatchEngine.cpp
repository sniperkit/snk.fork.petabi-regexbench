#include <dlfcn.h>

#include <stdexcept>

#include <rematch/compile.h>
#include <rematch/execute.h>
#include <rematch/rematch.h>

#include "REmatchEngine.h"

using namespace regexbench;

const char NFA_FUNC_NAME[] = "run";
const char NFA_NSTATES_NAME[] = "nstates";

REmatchAutomataEngine::REmatchAutomataEngine()
    : flow(nullptr), matcher(nullptr), txtbl(nullptr) {}

REmatchAutomataEngine::~REmatchAutomataEngine() {
  if (flow)
    mregflow_delete(flow);
  if (matcher)
    matcher_delete(matcher);
  if (txtbl)
    mregfree(txtbl);
}

void REmatchAutomataEngine::compile(const std::vector<Rule> &rules) {
  std::vector<const char *> exps;
  std::vector<unsigned> mods;
  std::vector<unsigned> ids;
  for (const auto &rule : rules) {
    exps.push_back(rule.getRegexp().data());
    ids.push_back(static_cast<unsigned>(rule.getID()));
    mods.push_back(rule.getPCRE2Options());
  }
  txtbl =
      rematch_compile(ids.data(), exps.data(), mods.data(), ids.size(), false);
  flow = mregflow_new(txtbl->nstates, 1, 1);
  matcher = matcher_new(txtbl->nstates);
}

void REmatchAutomataEngine::load(const std::string &filename) {
  txtbl = rematchload(filename.c_str());
  if (txtbl == nullptr) {
    throw std::runtime_error("cannot load NFA");
  }
  flow = mregflow_new(txtbl->nstates, 1, 1);
  if (flow == nullptr)
    throw std::bad_alloc();
  matcher = matcher_new(txtbl->nstates);
  if (matcher == nullptr)
    throw std::bad_alloc();
}

bool REmatchAutomataEngine::match(const char *data, size_t len) {
  MATCHER_SINGLE_CLEAN(matcher);
  mregexec_single(txtbl, data, len, 1, regmatch, matcher, flow);
  return matcher->matches > 0;
}

REmatchSOEngine::REmatchSOEngine()
    : run(nullptr), ctx(nullptr), dlhandle(nullptr) {}

REmatchSOEngine::~REmatchSOEngine() {
  if (ctx)
    destroy_matchctx(ctx);
  if (dlhandle)
    dlclose(dlhandle);
}

void REmatchSOEngine::load(const std::string &filename) {
  dlhandle = dlopen(filename.c_str(), RTLD_LAZY);
  if (dlhandle == nullptr) {
    char *error = dlerror();
    if (error != nullptr)
      throw std::runtime_error(error);
    throw std::runtime_error("fail to load " + filename);
  }
  size_t *p = reinterpret_cast<size_t *>(dlsym(dlhandle, NFA_NSTATES_NAME));
  if (p == nullptr) {
    char *error = dlerror();
    if (error != nullptr)
      throw std::runtime_error(error);
    throw std::runtime_error("cannot find symol");
  }
  ctx = create_matchctx(*p);
  if (ctx == nullptr)
    throw std::bad_alloc();
  run = reinterpret_cast<run_func_t>(dlsym(dlhandle, NFA_FUNC_NAME));
  if (run == nullptr) {
    char *error = dlerror();
    if (error != nullptr)
      throw std::runtime_error(error);
    throw std::runtime_error("cannot find symol");
  }
}

REmatchAutomataEngineSession::REmatchAutomataEngineSession()
    : parent{nullptr}, child{nullptr} {}
REmatchAutomataEngineSession::~REmatchAutomataEngineSession() {
  mregSession_delete_parent(parent);
  mregSession_delete_child(child);
}

bool REmatchAutomataEngineSession::match(const char *pkt, size_t len,
                                         size_t idx) {
  matcher_t *cur = child->mindex[idx];
  bool ret = false;
  switch (mregexec_session(txtbl, pkt, len, 1, regmatch, cur, child)) {
  case MREG_FINISHED: // finished
    cur->num_active = 0;
    ret = true;
    break;
  case MREG_NOT_FINISHED: // not finished
    ret = false;
    break;
  case MREG_FAILURE:
  default:
    cur->num_active = 0;
    ret = false;
  }
  return ret;
}

void REmatchAutomataEngineSession::init(size_t nsessions) {
  parent = mregSession_create_parent(static_cast<uint32_t>(nsessions * 2),
                                     txtbl->nstates);
  child = mregSession_create_child(parent, unit_total);

  for (size_t i = 0; i < nsessions * 2; i++) {
    matcher_t *cur = child->mindex[i];
    if (cur->num_active) {
      if (child->active1 < MNULL) {
        MATCHER_SESSION_SET_NEW(cur, child);
      } else {
        throw std::bad_alloc();
      }
    }
  }
}
