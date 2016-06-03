// -*- c++ -*-
#ifndef REGEXBENCH_REMATCHENGINE_H
#define REGEXBENCH_REMATCHENGINE_H

#include <rematch/rematch.h>

#include "Engine.h"
#include "session.h"

namespace regexbench {

class REmatchAutomataEngine : public Engine {
public:
  REmatchAutomataEngine();
  virtual ~REmatchAutomataEngine();

  virtual void compile(const std::vector<Rule> &);
  virtual void load(const std::string &);
  virtual bool match(const char *, size_t);

private:
  mregflow_t *flow;
  matcher_t *matcher;
protected:
  mregex_t *txtbl;
  mregmatch_t regmatch[1];
};

class REmatchSOEngine : public Engine {
  using run_func_t = bool (*)(const char *, size_t, matchctx_t *);

public:
  REmatchSOEngine();
  virtual ~REmatchSOEngine();

  virtual void load(const std::string &);
  virtual bool match(const char *data, size_t len) {
    return run(data, len, ctx);
  }

private:
  run_func_t run;
  matchctx_t *ctx;
  void *dlhandle;
};

class REmatchAutomataEngineSession : public REmatchAutomataEngine {
public:
  REmatchAutomataEngineSession();
  virtual ~REmatchAutomataEngineSession() = default;
  virtual void compile(const std::vector<Rule> &);
  virtual void init(const PcapSource &);

  using Engine::match;
  virtual bool match(const char *, size_t, size_t);
private:
  SessionTable sessionTable;
  mregSession_t *parent;
  mregSession_t *child;
};

} // namespace regexbench

#endif
