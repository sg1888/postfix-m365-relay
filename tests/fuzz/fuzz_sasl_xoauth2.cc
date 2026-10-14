// libFuzzer harness for the vendored sasl-xoauth2 plugin (vendor/sasl-xoauth2).
//
// Drives the unmodified plugin through its real SASL entry points, the way
// Postfix does, with attacker-shaped input in the three places it parses data:
//
//   mode 0  token file contents  (TokenStore::Read, then GetAccessToken)
//   mode 1  server challenge     (the JSON in a 334 reply after AUTH)
//   mode 2  token refresh reply  (the HTTP response body of a refresh)
//
// The first input byte picks the mode; the rest is the payload. Built with
// -fsanitize=fuzzer,address,undefined by tests/sasl-xoauth2-fuzz.sh, so any
// crash, memory error, leak or undefined behaviour is a finding.
//
// The server challenge is passed NUL-terminated with its length, as Postfix
// passes it (the plugin logs it with %s; upstream PR #128 makes that
// length-bounded). HTTP never leaves the process: an intercept answers.

#include <json/json.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "config.h"
#include "http.h"
#include "module.h"

namespace {

std::string g_token_path;
sasl_client_plug_t g_plug;

// What the HTTP intercept answers to a refresh request.
std::string g_refresh_body;
long g_refresh_code = 0;
int g_refresh_result = SASL_FAIL;

void WriteFile(const std::string &path, const uint8_t *data, size_t size) {
  FILE *f = fopen(path.c_str(), "wb");
  if (!f) abort();
  if (size && fwrite(data, 1, size, f) != size) abort();
  fclose(f);
}

void WriteFile(const std::string &path, const std::string &text) {
  WriteFile(path, reinterpret_cast<const uint8_t *>(text.data()), text.size());
}

std::string TokenJson(long expiry) {
  return R"({"access_token": "fuzz-access", "refresh_token": "fuzz-refresh", "expiry": ")" +
         std::to_string(expiry) + R"("})";
}

int GetAuthName(void *, int, const char **result, unsigned *len) {
  static const char kUser[] = "fuzz@example.invalid";
  *result = kUser;
  *len = sizeof(kUser) - 1;
  return SASL_OK;
}

// Like Postfix, the application owns the secret's memory.
int GetSecret(sasl_conn_t *, void *, int, sasl_secret_t **out) {
  static std::vector<unsigned char> buffer;
  buffer.assign(sizeof(sasl_secret_t) + g_token_path.size() + 1, 0);
  auto *secret = reinterpret_cast<sasl_secret_t *>(buffer.data());
  secret->len = g_token_path.size();
  memcpy(secret->data, g_token_path.data(), g_token_path.size());
  *out = secret;
  return SASL_OK;
}

int GetCallback(sasl_conn_t *, unsigned long id, sasl_callback_ft *ft, void **) {
  if (id == SASL_CB_AUTHNAME) {
    *ft = reinterpret_cast<sasl_callback_ft>(&GetAuthName);
    return SASL_OK;
  }
  if (id == SASL_CB_PASS) {
    *ft = reinterpret_cast<sasl_callback_ft>(&GetSecret);
    return SASL_OK;
  }
  return SASL_FAIL;
}

int CanonUser(sasl_conn_t *, const char *, unsigned, unsigned, sasl_out_params_t *) {
  return SASL_OK;
}

void *Malloc(size_t size) { return malloc(size); }
void Free(void *ptr) { free(ptr); }

// One SASL exchange: initial step, then (optionally) the server's challenge.
void Exchange(const std::string *challenge) {
  sasl_utils_t utils = {};
  utils.malloc = &Malloc;
  utils.free = &Free;
  utils.getcallback = &GetCallback;
  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &CanonUser;

  void *context = nullptr;
  if (g_plug.mech_new(nullptr, &params, &context) != SASL_OK) abort();
  const char *to_server = nullptr;
  unsigned to_server_len = 0;
  sasl_out_params_t out = {};
  int err = g_plug.mech_step(context, &params, nullptr, 0, nullptr, &to_server,
                             &to_server_len, &out);
  if (err == SASL_OK && challenge) {
    g_plug.mech_step(context, &params, challenge->c_str(),
                     static_cast<unsigned>(challenge->size()), nullptr,
                     &to_server, &to_server_len, &out);
  }
  g_plug.mech_dispose(context, &utils);
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  char dir[] = "/tmp/sxo-fuzz.XXXXXX";
  if (!mkdtemp(dir)) abort();
  g_token_path = std::string(dir) + "/token.json";

  // The relay's own settings: no logging out of the process.
  Json::Value config;
  config["client_id"] = "fuzz-client";
  config["client_secret"] = "";
  config["token_endpoint"] = "http://127.0.0.1:9/fuzz";
  config["always_log_to_syslog"] = "no";
  config["log_to_syslog_on_failure"] = "no";
  config["log_full_trace_on_failure"] = "no";
  if (sasl_xoauth2::Config::InitForTesting(config) != SASL_OK) abort();

  sasl_utils_t utils = {};
  int version = 0, count = 0;
  sasl_client_plug_t *plugs = nullptr;
  if (sasl_client_plug_init(&utils, SASL_CLIENT_PLUG_VERSION, &version, &plugs,
                            &count) != SASL_OK || count != 1) {
    abort();
  }
  g_plug = plugs[0];

  sasl_xoauth2::SetHttpInterceptForTesting(
      [](sasl_xoauth2::HttpPostOptions options) {
        *options.response_code = g_refresh_code;
        *options.response = g_refresh_body;
        if (g_refresh_result != SASL_OK) *options.error = "fuzz: no network";
        return g_refresh_result;
      });
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  const uint8_t mode = data[0] % 3;
  const uint8_t *payload = data + 1;
  const size_t length = size - 1;

  switch (mode) {
    case 0:  // Token file contents; any refresh it triggers fails.
      g_refresh_result = SASL_FAIL;
      WriteFile(g_token_path, payload, length);
      Exchange(nullptr);
      break;

    case 1: {  // Server challenge after a valid token was sent.
      g_refresh_result = SASL_FAIL;
      // Valid for an hour. (Not 2100: the vendored 0.28 cannot parse an
      // expiry past 2038; upstream PR #126.)
      WriteFile(g_token_path, TokenJson(static_cast<long>(time(nullptr)) + 3600));
      const std::string challenge(reinterpret_cast<const char *>(payload), length);
      Exchange(&challenge);
      break;
    }

    case 2:  // Refresh response for an expired token (code 200).
      WriteFile(g_token_path, TokenJson(0));
      g_refresh_result = SASL_OK;
      g_refresh_code = 200;
      g_refresh_body.assign(reinterpret_cast<const char *>(payload), length);
      Exchange(nullptr);
      break;
  }
  return 0;
}
