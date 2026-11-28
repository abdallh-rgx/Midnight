#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>

#include "includes/dobby/dobby.h"
#include "includes/logger.h"
#include "includes/opts.h"
#include "includes/hooks.h"

namespace {

// This offset is taken from the uploaded 22.40 owen.c table.
// It is valid only for the exact matching module/build and has not been
// independently verified against the target binary here.
constexpr uintptr_t kExecConsoleCommandOffset = 0xAA59BEC;
constexpr bool kEnableExecConsoleCommandHook = true;
constexpr bool kForceRhiSyncIntervalZero = true;

constexpr const char* kUnrealLibrary = "libUE4.so";
constexpr const char* kEosLibrary = "libEOSSDK.so";
constexpr const char* kCurlLibrary = "libUE4.so";
constexpr const char* kGameVersion = "++Fortnite+Release-18.40";

struct UEString {
    char16_t* data;
    int32_t length;
    int32_t capacity;
};

struct ParsedUrl {
    std::string host;
    std::string pathAndQuery;
};

using ProcessRequestFn = bool (*)(void*);
using SetUrlFn = void (*)(void*, const void*);
using ExecConsoleCommandFn = void (*)(void*, const void*, void*);
using CurlEasySetOptFn = int (*)(void*, int, void*);

std::atomic<bool> g_exec_hook_installed{false};
std::atomic<bool> g_rhi_command_sent{false};

ProcessRequestFn g_ue_process_request_original = nullptr;
ProcessRequestFn g_eos_process_request_original = nullptr;
SetUrlFn g_ue_set_url = nullptr;
SetUrlFn g_eos_set_url = nullptr;
ExecConsoleCommandFn g_exec_console_command_original = nullptr;
CurlEasySetOptFn g_curl_easy_setopt_original = nullptr;

bool ContainsVersionString(const uint8_t* memory, size_t size, bool utf16) {
    if (!memory) return false;
    const size_t length = std::strlen(kGameVersion);
    if (!length || size < (utf16 ? length * 2 : length)) return false;

    if (!utf16) {
        for (size_t i = 0; i + length <= size; ++i) {
            if (std::memcmp(memory + i, kGameVersion, length) == 0) return true;
        }
        return false;
    }

    for (size_t i = 0; i + length * 2 <= size; ++i) {
        bool match = true;
        for (size_t j = 0; j < length; ++j) {
            if (memory[i + j * 2] != static_cast<uint8_t>(kGameVersion[j]) ||
                memory[i + j * 2 + 1] != 0) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

bool HasExpectedVersionInLibrary(const char* libraryName) {
    FILE* maps = std::fopen("/proc/self/maps", "r");
    if (!maps) return false;

    char line[1024];
    bool found = false;
    while (std::fgets(line, sizeof(line), maps)) {
        if (!std::strstr(line, libraryName)) continue;

        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long fileOffset = 0;
        char permissions[8] = {};
        if (std::sscanf(line, "%lx-%lx %7s %lx", &start, &end,
                        permissions, &fileOffset) < 4 || permissions[0] != 'r' ||
            end <= start) {
            continue;
        }

        const auto* region = reinterpret_cast<const uint8_t*>(
            static_cast<uintptr_t>(start));
        const size_t regionSize = static_cast<size_t>(end - start);
        if (ContainsVersionString(region, regionSize, false) ||
            ContainsVersionString(region, regionSize, true)) {
            found = true;
            break;
        }
    }

    std::fclose(maps);
    return found;
}

void* GetLibraryBase(const char* libraryName) {
    if (!libraryName || !*libraryName) return nullptr;

    FILE* maps = std::fopen("/proc/self/maps", "r");
    if (!maps) return nullptr;

    char line[1024];
    uintptr_t firstMatch = 0;
    while (std::fgets(line, sizeof(line), maps)) {
        if (!std::strstr(line, libraryName)) continue;

        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long fileOffset = 0;
        char permissions[8] = {};
        if (std::sscanf(line, "%lx-%lx %7s %lx", &start, &end,
                        permissions, &fileOffset) < 4) {
            continue;
        }

        if (!firstMatch) firstMatch = static_cast<uintptr_t>(start);
        if (fileOffset == 0) {
            std::fclose(maps);
            return reinterpret_cast<void*>(static_cast<uintptr_t>(start));
        }
    }

    std::fclose(maps);
    return reinterpret_cast<void*>(firstMatch);
}

static std::string LowerAscii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return value;
}

bool ParseUrl(const char* input, ParsedUrl& output) {
    output.host.clear();
    output.pathAndQuery.clear();
    if (!input || !*input) return false;

    const char* scheme = std::strstr(input, "://");
    if (!scheme) return false;

    const char* authority = scheme + 3;
    const char* path = std::strpbrk(authority, "/?#");
    const char* authorityEnd = path ? path : input + std::strlen(input);
    if (authorityEnd <= authority) return false;

    output.host.assign(authority, static_cast<size_t>(authorityEnd - authority));
    output.host = LowerAscii(output.host);

    if (!path) {
        output.pathAndQuery = "/";
    } else if (*path == '/') {
        const char* fragment = std::strchr(path, '#');
        output.pathAndQuery.assign(path, fragment ?
            static_cast<size_t>(fragment - path) : std::strlen(path));
    } else if (*path == '?') {
        const char* fragment = std::strchr(path, '#');
        output.pathAndQuery = "/";
        output.pathAndQuery.append(path, fragment ?
            static_cast<size_t>(fragment - path) : std::strlen(path));
    } else {
        output.pathAndQuery = "/";
    }

    const size_t colon = output.host.find(':');
    if (colon != std::string::npos) output.host.resize(colon);
    return !output.host.empty();
}

bool ShouldRedirectHost(const std::string& host) {
    static const char* const domains[] = {
        "game-social.epicgames.com",
        "ol.epicgames.com",
        "ol.epicgames.net",
        "on.epicgames.com",
        "ak.epicgames.com",
        "epicgames.dev"
    };

    for (const char* domain : domains) {
        const size_t domainLength = std::strlen(domain);
        if (host == domain) return true;
        if (host.size() > domainLength &&
            host.compare(host.size() - domainLength, domainLength, domain) == 0 &&
            host[host.size() - domainLength - 1] == '.') {
            return true;
        }
    }
    return false;
}

std::string MakeBackendUrl(const std::string& pathAndQuery) {
    std::string backend(BACKEND_URL);
    while (!backend.empty() && backend.back() == '/') backend.pop_back();
    if (pathAndQuery.empty()) return backend + "/";
    if (pathAndQuery.front() != '/') backend.push_back('/');
    backend += pathAndQuery;
    return backend;
}

std::string FStringToUtf8(const UEString* value) {
    std::string result;
    if (!value || !value->data || value->length <= 0) return result;

    const int32_t count = value->length - 1; // FString::Num includes the terminator.
    for (int32_t i = 0; i < count; ++i) {
        uint32_t codePoint = value->data[i];
        if (codePoint >= 0xD800 && codePoint <= 0xDBFF && i + 1 < count) {
            const uint32_t low = value->data[i + 1];
            if (low >= 0xDC00 && low <= 0xDFFF) {
                codePoint = 0x10000 + ((codePoint - 0xD800) << 10) + (low - 0xDC00);
                ++i;
            }
        }

        if (codePoint <= 0x7F) {
            result.push_back(static_cast<char>(codePoint));
        } else if (codePoint <= 0x7FF) {
            result.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
            result.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        } else if (codePoint <= 0xFFFF) {
            result.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
            result.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
            result.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
    }
    return result;
}

bool Utf8ToFString(const std::string& input, std::vector<char16_t>& storage,
                   UEString& output) {
    storage.clear();
    storage.reserve(input.size() + 1);

    const unsigned char* cursor =
        reinterpret_cast<const unsigned char*>(input.c_str());
    while (*cursor) {
        uint32_t codePoint = 0;
        if (*cursor < 0x80) {
            codePoint = *cursor++;
        } else if ((*cursor & 0xE0) == 0xC0 && cursor[1]) {
            codePoint = ((cursor[0] & 0x1F) << 6) | (cursor[1] & 0x3F);
            cursor += 2;
        } else if ((*cursor & 0xF0) == 0xE0 && cursor[1] && cursor[2]) {
            codePoint = ((cursor[0] & 0x0F) << 12) |
                        ((cursor[1] & 0x3F) << 6) | (cursor[2] & 0x3F);
            cursor += 3;
        } else if ((*cursor & 0xF8) == 0xF0 && cursor[1] && cursor[2] && cursor[3]) {
            codePoint = ((cursor[0] & 0x07) << 18) |
                        ((cursor[1] & 0x3F) << 12) |
                        ((cursor[2] & 0x3F) << 6) | (cursor[3] & 0x3F);
            cursor += 4;
        } else {
            return false;
        }

        if (codePoint <= 0xFFFF) {
            storage.push_back(static_cast<char16_t>(codePoint));
        } else {
            codePoint -= 0x10000;
            storage.push_back(static_cast<char16_t>(0xD800 + (codePoint >> 10)));
            storage.push_back(static_cast<char16_t>(0xDC00 + (codePoint & 0x3FF)));
        }
    }

    storage.push_back(u'\0');
    output.data = storage.data();
    output.length = static_cast<int32_t>(storage.size());
    output.capacity = output.length;
    return true;
}

bool RedirectFStringAtOffset(void* request, uintptr_t getUrlOffset,
                              SetUrlFn setUrl, const char* label) {
    if (!request || !setUrl || !getUrlOffset) return false;

    auto* currentUrl = reinterpret_cast<UEString*>(
        reinterpret_cast<uintptr_t>(request) + getUrlOffset);
    const std::string original = FStringToUtf8(currentUrl);
    if (original.empty()) return false;

    ParsedUrl parsed;
    if (!ParseUrl(original.c_str(), parsed) || !ShouldRedirectHost(parsed.host)) {
        return false;
    }

    const std::string redirected = MakeBackendUrl(parsed.pathAndQuery);
    std::vector<char16_t> newUrlStorage;
    UEString newUrl{};
    if (!Utf8ToFString(redirected, newUrlStorage, newUrl)) return false;

    setUrl(request, &newUrl);
    LOGI("[%s] URL redirect: %s -> %s", label, original.c_str(), redirected.c_str());
    return true;
}

// -------------------- FCurlRequest / EOS request hooks --------------------

bool FCurlProcessRequestHook(void* request) {
    if (!g_ue_process_request_original) return false;
    RedirectFStringAtOffset(request, FCurlHookOpts::GETURL_ADDR,
                            g_ue_set_url, "UE");
    return g_ue_process_request_original(request);
}

bool EOSProcessRequestHook(void* request) {
    if (!g_eos_process_request_original) return false;
    RedirectFStringAtOffset(request, EOSFCurlHookOpts::GETURL_ADDR,
                            g_eos_set_url, "EOS");
    return g_eos_process_request_original(request);
}

// -------------------- ExecConsoleCommand / RHI enforcement --------------------

void ExecConsoleCommandHook(void* worldContext, const void* command, void* output) {
    if (!g_exec_console_command_original) return;

    // Preserve the game's original command first.
    g_exec_console_command_original(worldContext, command, output);

    // Re-apply on the same calling thread after every console command.
    // This avoids calling Unreal UObject/console code from a detached worker thread.
    static thread_local bool injectingRhiCommand = false;
    if (!kForceRhiSyncIntervalZero || injectingRhiCommand || !worldContext) return;

    injectingRhiCommand = true;
    const char16_t commandText[] = u"rhi.SyncInterval 0";
    UEString forceCommand{};
    forceCommand.data = const_cast<char16_t*>(commandText);
    forceCommand.length = static_cast<int32_t>(sizeof(commandText) / sizeof(commandText[0]));
    forceCommand.capacity = forceCommand.length;

    g_exec_console_command_original(worldContext, &forceCommand, output);

    if (!g_rhi_command_sent.exchange(true)) {
        LOGI("RHI: re-applied rhi.SyncInterval 0 through ExecConsoleCommand");
    }
    injectingRhiCommand = false;
}

// -------------------- curl_easy_setopt hook (libUE4.so variant) --------------------

int CurlEasySetOptHook(void* curl, int option, void* argument) {
    if (!g_curl_easy_setopt_original) return -1;

    // CURLOPT_URL = 10002
    if (option == 10002 && argument) {
        const char* original = static_cast<const char*>(argument);
        ParsedUrl parsed;
        if (ParseUrl(original, parsed) && ShouldRedirectHost(parsed.host)) {
            static thread_local std::string redirected;
            redirected = MakeBackendUrl(parsed.pathAndQuery);
            LOGI("[curl] URL redirect: %s -> %s", original, redirected.c_str());
            return g_curl_easy_setopt_original(curl, option,
                                                const_cast<char*>(redirected.c_str()));
        }
    }

    // CURLOPT_SSL_VERIFYPEER = 64; CURLOPT_SSL_VERIFYHOST = 81.
    // This is optional and only used when BYPASS_SSL is explicitly enabled.
    if (BYPASS_SSL && (option == 64 || option == 81)) {
        return g_curl_easy_setopt_original(curl, option, nullptr);
    }

    return g_curl_easy_setopt_original(curl, option, argument);
}

bool InstallUEHooks(void* base) {
    if (!base) return false;
    bool anyInstalled = false;

    if (FCurlHookOpts::USE_PR && FCurlHookOpts::PR_ADDR &&
        FCurlHookOpts::SETURL_ADDR && FCurlHookOpts::GETURL_ADDR) {
        g_ue_set_url = reinterpret_cast<SetUrlFn>(
            reinterpret_cast<uintptr_t>(base) + FCurlHookOpts::SETURL_ADDR);
        void* target = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(base) + FCurlHookOpts::PR_ADDR);
        if (DobbyHook(target, reinterpret_cast<void*>(FCurlProcessRequestHook),
                      reinterpret_cast<void**>(&g_ue_process_request_original)) == 0) {
            LOGI("UE ProcessRequest hook installed");
            anyInstalled = true;
        } else {
            LOGE("UE ProcessRequest hook failed");
        }
    }

    if (kEnableExecConsoleCommandHook && kExecConsoleCommandOffset) {
        void* target = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(base) + kExecConsoleCommandOffset);
        if (DobbyHook(target, reinterpret_cast<void*>(ExecConsoleCommandHook),
                      reinterpret_cast<void**>(&g_exec_console_command_original)) == 0) {
            g_exec_hook_installed.store(true);
            LOGI("ExecConsoleCommand hook installed at +0x%lx",
                 static_cast<unsigned long>(kExecConsoleCommandOffset));
            anyInstalled = true;
        } else {
            LOGE("ExecConsoleCommand hook failed");
        }
    }

    return anyInstalled;
}

bool InstallEOSHooks(void* base) {
    if (!base || !EOSFCurlHookOpts::USE_EOS ||
        !EOSFCurlHookOpts::PR_ADDR || !EOSFCurlHookOpts::SETURL_ADDR ||
        !EOSFCurlHookOpts::GETURL_ADDR) {
        return false;
    }

    g_eos_set_url = reinterpret_cast<SetUrlFn>(
        reinterpret_cast<uintptr_t>(base) + EOSFCurlHookOpts::SETURL_ADDR);
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(base) + EOSFCurlHookOpts::PR_ADDR);

    if (DobbyHook(target, reinterpret_cast<void*>(EOSProcessRequestHook),
                  reinterpret_cast<void**>(&g_eos_process_request_original)) == 0) {
        LOGI("EOS ProcessRequest hook installed");
        return true;
    }

    LOGE("EOS ProcessRequest hook failed");
    return false;
}

bool InstallCurlHookIfAvailable() {
    void* handle = dlopen(kCurlLibrary, RTLD_NOW | RTLD_NOLOAD);
    if (!handle) return false;

    void* symbol = dlsym(handle, "curl_easy_setopt");
    bool installed = false;
    if (symbol) {
        if (DobbyHook(symbol, reinterpret_cast<void*>(CurlEasySetOptHook),
                      reinterpret_cast<void**>(&g_curl_easy_setopt_original)) == 0) {
            LOGI("curl_easy_setopt hook installed");
            installed = true;
        } else {
            LOGE("curl_easy_setopt hook failed");
        }
    } else {
        LOGE("curl_easy_setopt symbol not found in %s", kCurlLibrary);
    }

    dlclose(handle);
    return installed;
}

 } // namespace

// Public setup functions called by main.cpp. The previous source only had
// anonymous-namespace helpers, so these required symbols were never emitted.
namespace Hooks {

void* FCurlHook::SetupHook(void* handle) {
    (void)handle;

    void* ueBase = nullptr;
    for (int attempt = 0; attempt < 75 && !ueBase; ++attempt) {
        ueBase = GetLibraryBase(kUnrealLibrary);
        if (!ueBase) usleep(200000);
    }

    if (!ueBase) {
        LOGE("%s not found; UE hooks skipped", kUnrealLibrary);
        return nullptr;
    }

    if (!HasExpectedVersionInLibrary(kUnrealLibrary)) {
        LOGE("Expected build string not found; 22.40 UE offsets were not installed");
        return nullptr;
    }

    LOGI("Verified target build string: %s", kGameVersion);
    InstallUEHooks(ueBase);
    return nullptr;
}

void* EOSFCurlHook::SetupHook(void* handle) {
    (void)handle;

    // Do not apply build-specific EOS offsets until the matching UE build
    // has been identified in this process.
    void* ueBase = nullptr;
    for (int attempt = 0; attempt < 75 && !ueBase; ++attempt) {
        ueBase = GetLibraryBase(kUnrealLibrary);
        if (!ueBase) usleep(200000);
    }

    if (!ueBase || !HasExpectedVersionInLibrary(kUnrealLibrary)) {
        LOGE("Matching 22.40 UE build not found; EOS hook skipped");
        return nullptr;
    }

    void* eosBase = nullptr;
    for (int attempt = 0; attempt < 75 && !eosBase; ++attempt) {
        eosBase = GetLibraryBase(kEosLibrary);
        if (!eosBase) usleep(200000);
    }

    if (!eosBase) {
        LOGI("%s not loaded; EOS hook skipped", kEosLibrary);
        return nullptr;
    }

    InstallEOSHooks(eosBase);
    return nullptr;
}

namespace CurlHook {
void* SetupHook(void* handle) {
    (void)handle;
    for (int attempt = 0; attempt < 75; ++attempt) {
        if (InstallCurlHookIfAvailable()) break;
        usleep(200000);
    }
    return nullptr;
}
} // namespace CurlHook

} // namespace Hooks
