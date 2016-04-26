#include "PCRE.h"

using namespace regexbench;

PCREEngine::PCREEngine() {

}

PCREEngine::~PCREEngine() {
}

void PCREEngine::compile(const std::vector<Rule> &rules) {
  for (const auto &rule : rules) {
  }
}

bool PCREEngine::match(const char *data, size_t len) {
}
