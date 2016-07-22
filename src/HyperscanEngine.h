// -*- c++ -*-
#ifndef REGEXBENCH_HYPERSCANENGINE_H
#define REGEXBENCH_HYPERSCANENGINE_H

#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>

#include "Engine.h"

namespace regexbench {

class HyperscanEngine : public Engine {
public:
  HyperscanEngine();
  HyperscanEngine(const HyperscanEngine &) = delete;
  HyperscanEngine(HyperscanEngine &&o) : db(o.db), scratch(o.scratch) {
    o.db = nullptr;
    o.scratch = nullptr;
  }
  virtual ~HyperscanEngine();
  HyperscanEngine &operator=(const HyperscanEngine &) = delete;
  HyperscanEngine &operator=(HyperscanEngine &&o) {
    hs_free_database(db);
    db = o.db;
    o.db = nullptr;
    hs_free_scratch(scratch);
    scratch = o.scratch;
    o.scratch = nullptr;
    return *this;
  }

  virtual void compile(const std::vector<Rule> &);
  virtual size_t match(const char *, size_t, size_t);

protected:
  void reportFailedRules(const std::vector<Rule> &);
  hs_database_t *db;
  hs_scratch_t *scratch;
  hs_platform_info_t platform;
  size_t nsessions;
};

class HyperscanEngineStream : public HyperscanEngine {
public:
  HyperscanEngineStream() = default;
  virtual ~HyperscanEngineStream();
  virtual void init(size_t);

  void compile(const std::vector<Rule> &);
  virtual size_t match(const char *, size_t, size_t);

private:
  std::unique_ptr<hs_stream*[]> streams;
};

} // namespace regexbench

#endif
