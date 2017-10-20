// -*- c++ -*-
#ifndef REGEXBENCH_REMATCHENGINE_H
#define REGEXBENCH_REMATCHENGINE_H

#include <atomic>
#include <map>
#include <memory>

#include <rematch/compile.h>
#include <rematch/execute.h>
#include <rematch/rematch.h>

#include "Engine.h"
#include "Session.h"

namespace regexbench {

constexpr unsigned REMATCH_VERSION_MAJOR_REQ = 1;
constexpr unsigned REMATCH_VERSION_MINOR_REQ = 10;
static_assert(REMATCH_VERSION_MAJOR > REMATCH_VERSION_MAJOR_REQ ||
                  REMATCH_VERSION_MAJOR == REMATCH_VERSION_MAJOR_REQ &&
                      REMATCH_VERSION_MINOR >= REMATCH_VERSION_MINOR_REQ,
              "rematch>=1.10 is required.");

class REmatchAutomataEngine : public Engine {
public:
  REmatchAutomataEngine(uint32_t nm = 1, bool red = false);
  virtual ~REmatchAutomataEngine();

  virtual void compile(const std::vector<Rule>&, size_t = 1);
  virtual void load(const std::string&, size_t = 1);
  virtual size_t match(const char*, size_t, size_t, size_t = 0,
                       size_t* = nullptr);

private:
  mregflow_t* flow;
  matcher_t* matcher;

protected:
  mregex_t* txtbl;
  std::unique_ptr<mregmatch_t[]> regmatchMem;
  mregmatch_t* regmatch;
  static constexpr uint32_t MAX_NMATCH = 32; // TODO
  const uint32_t nmatch;
  bool reduce = false;
  char __padding[3];
};

class REmatchSOEngine : public Engine {
  using run_func_t = bool (*)(const char*, size_t, matchctx_t*);

public:
  REmatchSOEngine();
  virtual ~REmatchSOEngine();

  virtual void load(const std::string&, size_t = 1);
  virtual size_t match(const char* data, size_t len, size_t, size_t = 0,
                       size_t* = nullptr)
  {
    return run(data, len, ctx);
  }

private:
  run_func_t run;
  matchctx_t* ctx;
  void* dlhandle;
};

#ifdef WITH_SESSION
class REmatchAutomataEngineSession : public REmatchAutomataEngine {
public:
  REmatchAutomataEngineSession(uint32_t nm = 1);
  virtual ~REmatchAutomataEngineSession();
  virtual void init(size_t);

  using Engine::match;
  virtual size_t match(const char*, size_t, size_t, size_t = 0,
                       size_t* = nullptr);

private:
  static constexpr size_t unit_total = 1u << 17;
  mregSession_t* parent;
  mregSession_t* child;
};
#endif

class REmatch2AutomataEngine : public Engine {
public:
  REmatch2AutomataEngine(uint32_t nm = 1, bool red = false, bool turbo = false);
  ~REmatch2AutomataEngine();

  void compile(const std::vector<Rule>& rules, size_t = 1) override;
  void compile_test(const std::vector<Rule>&) const override;
  void update_test(const std::vector<Rule>&) override;
  void load(const std::string& file, size_t = 1) override;
  size_t match(const char* pkt, size_t len, size_t, size_t = 0,
               size_t* = nullptr) override;

private:
  void load_updated(const std::string& file); // for possible use

  std::map<int, rematch2_t*> matchers; // TODO: we need to implement
                                       // garbage collector to reap
                                       // outdated matchers
  std::vector<rematch_match_context_t*> contexts;
  std::vector<rematch_scratch_t*> scratches;
  std::vector<int> versions;
  const uint32_t nmatch;
  std::atomic_int version;
  bool reduce = false;
  bool turbo = false;

protected:
  char __padding[6];
};

} // namespace regexbench

#endif
