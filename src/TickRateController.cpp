#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/ModMenu.hpp>
#include <pl/memory/Hook.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <link.h>
#include <elf.h>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr const char* MODULE_ID = "tickrate_controller";
constexpr uintptr_t LEGACY_RVA = 0x0F9E26C0;  // 1.26.52.3

// Prologue fingerprint of the function at 0xF9E26C0 in 1.26.52.3.
constexpr uint32_t SIGNATURE[] = {
    0xd100c3ff, 0xa9017bfd, 0xa9024ff4, 0x910043fd,
    0xd53bd054, 0xaa0003f3, 0xf9401688, 0xf90007e8,
};
constexpr size_t SIGNATURE_WORDS =
    sizeof(SIGNATURE) / sizeof(SIGNATURE[0]);

std::atomic<int> targetTps{20};
std::atomic<uint64_t> detourCalls{0};
std::atomic<uint64_t> originalCalls{0};
std::atomic<int> tickPhase{0};
std::atomic_bool hookInstalled{false};

void* originalPlayerNormalTick = nullptr;
void* playerNormalTickAddress = nullptr;

std::filesystem::path diagnosticPath;
std::mutex diagnosticMutex;

void writeDiagnosticLine(const std::string& line) {
    std::lock_guard<std::mutex> lock(diagnosticMutex);
    if (diagnosticPath.empty()) return;
    std::ofstream out(diagnosticPath, std::ios::app);
    if (out) {
        out << line << '\n';
        out.flush();
    }
}

std::string pointerToHex(const void* ptr) {
    std::ostringstream out;
    out << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
    return out.str();
}

std::string numberToHex(uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

struct LibInfo {
    uintptr_t base = 0;
    bool found = false;
    std::string buildId;
    std::vector<std::pair<uintptr_t, size_t>> exec;
};

int inspectLib(dl_phdr_info* info, size_t, void* user) {
    if (!info || !info->dlpi_name || !user ||
        !std::strstr(info->dlpi_name, "libminecraftpe.so")) {
        return 0;
    }

    auto* r = static_cast<LibInfo*>(user);
    r->base = static_cast<uintptr_t>(info->dlpi_addr);
    r->found = true;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const auto& ph = info->dlpi_phdr[i];

        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
            r->exec.emplace_back(
                static_cast<uintptr_t>(info->dlpi_addr + ph.p_vaddr),
                static_cast<size_t>(ph.p_filesz));
        }

        if (ph.p_type == PT_NOTE && r->buildId.empty()) {
            auto* n = reinterpret_cast<const unsigned char*>(
                info->dlpi_addr + ph.p_vaddr);
            size_t rem = ph.p_memsz;

            while (rem >= sizeof(ElfW(Nhdr))) {
                ElfW(Nhdr) h{};
                std::memcpy(&h, n, sizeof(h));

                const size_t ns = (h.n_namesz + 3u) & ~size_t(3u);
                const size_t ds = (h.n_descsz + 3u) & ~size_t(3u);
                const size_t total = sizeof(ElfW(Nhdr)) + ns + ds;
                if (total > rem) break;

                const unsigned char* desc = n + sizeof(ElfW(Nhdr)) + ns;

                if (h.n_type == NT_GNU_BUILD_ID) {
                    static const char hex[] = "0123456789abcdef";
                    for (size_t j = 0; j < h.n_descsz && j < 32; ++j) {
                        r->buildId += hex[(desc[j] >> 4) & 0x0F];
                        r->buildId += hex[desc[j] & 0x0F];
                    }
                    break;
                }

                n += total;
                rem -= total;
            }
        }
    }
    return 1;
}

// Returns RVAs of every SIGNATURE match in executable segments (max 16).
std::vector<uintptr_t> scanForSignature(const LibInfo& lib) {
    std::vector<uintptr_t> hits;

    for (const auto& seg : lib.exec) {
        const auto* w = reinterpret_cast<const uint32_t*>(seg.first);
        const size_t count = seg.second / sizeof(uint32_t);
        if (count < SIGNATURE_WORDS) continue;

        for (size_t i = 0; i + SIGNATURE_WORDS <= count; ++i) {
            if (w[i] != SIGNATURE[0]) continue;
            if (std::memcmp(w + i, SIGNATURE, sizeof(SIGNATURE)) == 0) {
                hits.push_back(seg.first + i * sizeof(uint32_t) - lib.base);
                if (hits.size() >= 16) return hits;
            }
        }
    }
    return hits;
}

// Radio values are indices: 0=20, 1=15, 2=10, 3=5, 4=Reset(20).
bool parseTpsOption(std::string_view v, int& out) {
    if (v == "0" || v == "20" || v == "20 TPS") out = 20;
    else if (v == "1" || v == "15" || v == "15 TPS") out = 15;
    else if (v == "2" || v == "10" || v == "10 TPS") out = 10;
    else if (v == "3" || v == "5" || v == "5 TPS") out = 5;
    else if (v == "4" || v == "Reset" || v == "Reset (20 TPS)") out = 20;
    else return false;
    return true;
}

// ---------------- DIAGNOSTIC: per-second rate reporter ----------------
std::atomic<void*> lastSelf{nullptr};
std::atomic<uint64_t> selfChanges{0};
std::atomic_bool reporterRun{false};
std::thread reporterThread;

void startReporter() {
    if (reporterRun.exchange(true)) return;

    reporterThread = std::thread([] {
        uint64_t lastD = 0, lastO = 0, lastS = 0;

        while (reporterRun.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!reporterRun.load()) break;

            const uint64_t d = detourCalls.load();
            const uint64_t o = originalCalls.load();
            const uint64_t s = selfChanges.load();

            writeDiagnosticLine(
                "[RATE] tps=" + std::to_string(targetTps.load()) +
                " detour/s=" + std::to_string(d - lastD) +
                " original/s=" + std::to_string(o - lastO) +
                " selfChanges/s=" + std::to_string(s - lastS) +
                " lastSelf=" + pointerToHex(lastSelf.load()));

            lastD = d;
            lastO = o;
            lastS = s;
        }
    });
}

void stopReporter() {
    reporterRun.store(false);
    if (reporterThread.joinable()) reporterThread.join();
}

void playerNormalTickDetour(void* self) {
    detourCalls.fetch_add(1, std::memory_order_relaxed);

    if (lastSelf.exchange(self, std::memory_order_relaxed) != self) {
        selfChanges.fetch_add(1, std::memory_order_relaxed);
    }

    void* original = originalPlayerNormalTick;
    if (!original) return;

    const int tps = targetTps.load(std::memory_order_relaxed);

    if (tps >= 20 || tps <= 0) {
        tickPhase.store(0, std::memory_order_relaxed);
        reinterpret_cast<void (*)(void*)>(original)(self);
        originalCalls.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    int phase = tickPhase.load(std::memory_order_relaxed);

    for (;;) {
        int next = phase + tps;
        const bool shouldRun = next >= 20;
        if (shouldRun) next -= 20;

        if (tickPhase.compare_exchange_weak(
                phase, next,
                std::memory_order_relaxed, std::memory_order_relaxed)) {
            if (!shouldRun) return;
            break;
        }
    }

    reinterpret_cast<void (*)(void*)>(original)(self);
    originalCalls.fetch_add(1, std::memory_order_relaxed);
}

bool installPlayerHook(ll::mod::NativeMod& mod) {
    auto& logger = mod.getLogger();

    writeDiagnosticLine("[CHECK] Hook installation started.");

    if (hookInstalled.load(std::memory_order_relaxed)) return true;

    LibInfo lib{};
    dl_iterate_phdr(inspectLib, &lib);

    if (!lib.found) {
        writeDiagnosticLine("[FAIL] Minecraft library not found.");
        logger.error("TickRate Controller: Minecraft library not found.");
        return false;
    }

    writeDiagnosticLine("[OK] Library base=" +
        pointerToHex(reinterpret_cast<void*>(lib.base)));
    writeDiagnosticLine("[INFO] Build ID=" + lib.buildId);
    writeDiagnosticLine("[INFO] Exec segments=" +
        std::to_string(lib.exec.size()));

    const std::vector<uintptr_t> hits = scanForSignature(lib);
    writeDiagnosticLine("[SCAN] hits=" + std::to_string(hits.size()));

    for (uintptr_t rva : hits) {
        uint32_t next[8]{};
        std::memcpy(next,
            reinterpret_cast<const void*>(lib.base + rva + sizeof(SIGNATURE)),
            sizeof(next));

        std::ostringstream line;
        line << "[SCAN] hit RVA=" << numberToHex(rva)
             << " next words:" << std::hex;
        for (uint32_t w : next) line << ' ' << w;
        writeDiagnosticLine(line.str());
    }

    uintptr_t chosen = 0;
    bool have = false;

    for (uintptr_t rva : hits) {
        if (rva == LEGACY_RVA) { chosen = rva; have = true; break; }
    }
    if (!have && hits.size() == 1) { chosen = hits[0]; have = true; }

    if (!have) {
        writeDiagnosticLine(hits.empty()
            ? "[FAIL] Signature not found in this build. Hook skipped."
            : "[FAIL] Multiple hits; refusing to guess. Hook skipped.");
        logger.error("TickRate Controller: could not resolve player tick.");
        return false;
    }

    writeDiagnosticLine("[SCAN] Chosen RVA=" + numberToHex(chosen));

    playerNormalTickAddress = reinterpret_cast<void*>(lib.base + chosen);
    writeDiagnosticLine("[CHECK] Hook target=" +
        pointerToHex(playerNormalTickAddress));

    const int result = pl::memory::hook(
        playerNormalTickAddress,
        reinterpret_cast<void*>(&playerNormalTickDetour),
        &originalPlayerNormalTick);

    writeDiagnosticLine("[CHECK] Hook return code=" + std::to_string(result));
    writeDiagnosticLine("[CHECK] Original function pointer=" +
        pointerToHex(originalPlayerNormalTick));

    if (result != 0 || !originalPlayerNormalTick) {
        writeDiagnosticLine("[FAIL] Hook failed or original pointer is null.");
        logger.error("TickRate Controller: Player tick hook failed.");
        playerNormalTickAddress = nullptr;
        originalPlayerNormalTick = nullptr;
        return false;
    }

    tickPhase.store(0, std::memory_order_relaxed);
    detourCalls.store(0, std::memory_order_relaxed);
    originalCalls.store(0, std::memory_order_relaxed);
    selfChanges.store(0, std::memory_order_relaxed);
    lastSelf.store(nullptr, std::memory_order_relaxed);

    hookInstalled.store(true, std::memory_order_relaxed);
    startReporter();

    writeDiagnosticLine("[OK] Hook installation succeeded.");
    logger.info("TickRate Controller: player-tick hook installed.");
    return true;
}

void removePlayerHook(ll::mod::NativeMod& mod) {
    if (!hookInstalled.load(std::memory_order_relaxed)) return;

    stopReporter();

    const bool removed = pl::memory::unhook(
        playerNormalTickAddress,
        reinterpret_cast<void*>(&playerNormalTickDetour));

    if (removed) {
        writeDiagnosticLine("[INFO] Hook removed successfully.");
        hookInstalled.store(false, std::memory_order_relaxed);
        playerNormalTickAddress = nullptr;
        originalPlayerNormalTick = nullptr;
        tickPhase.store(0, std::memory_order_relaxed);
        mod.getLogger().info("TickRate Controller: hook removed.");
    } else {
        writeDiagnosticLine("[FAIL] Hook removal failed.");
        mod.getLogger().error("TickRate Controller: failed to remove hook.");
    }
}

class TickRateController {
public:
    TickRateController()
        : self(*ll::mod::NativeMod::current()) {}

    ll::mod::NativeMod& getSelf() const { return self; }

    bool load() {
        diagnosticPath = getSelf().getDataDir() / "diagnostic.txt";

        std::error_code ec;
        std::filesystem::create_directories(diagnosticPath.parent_path(), ec);

        {
            std::lock_guard<std::mutex> lock(diagnosticMutex);
            std::ofstream out(diagnosticPath, std::ios::trunc);
            if (out) {
                out << "=== TickRateController Diagnostics ===\n";
                out << "Build: runtime signature scan\n";
                out << "Radio mapping: 0=20, 1=15, 2=10, 3=5, 4=Reset/20\n";
                out << "Mod load stage: OK\n";
                out.flush();
            }
        }

        if (ec) {
            getSelf().getLogger().error(
                "Diagnostic directory creation failed: {}", ec.message());
        }

        getSelf().getLogger().info("TickRate Controller loaded.");
        return true;
    }

    bool enable() {
        pl::modmenu::ModuleBuilder builder(MODULE_ID, "TickRate Controller");

        builder
            .modId(getSelf().getId())
            .description(
                "Experimental player-tick throttling only. "
                "Does not change full-world or server TPS.")
            .defaultEnabled(true)
            .config(
                "target_tps",
                "Target TPS",
                pl::modmenu::ConfigType::Radio,
                "0",
                "20 TPS,15 TPS,10 TPS,5 TPS,Reset (20 TPS)")
            .onConfigChanged(
                [this](std::string_view moduleId,
                       std::string_view key,
                       std::string_view value) {
                    if (moduleId != MODULE_ID || key != "target_tps") return;

                    writeDiagnosticLine("[CONFIG] Raw radio value=[" +
                        std::string(value) + "]");

                    int selected = 20;
                    if (!parseTpsOption(value, selected)) {
                        writeDiagnosticLine("[WARN] Unknown TPS option=[" +
                            std::string(value) + "]");
                        return;
                    }

                    targetTps.store(selected, std::memory_order_relaxed);
                    tickPhase.store(0, std::memory_order_relaxed);

                    writeDiagnosticLine("[CONFIG] Selected TPS=" +
                        std::to_string(selected));
                    writeDiagnosticLine(std::string("[STATUS] Hook installed: ") +
                        (hookInstalled.load() ? "YES" : "NO"));

                    getSelf().getLogger().info(
                        "Selected experimental player tick rate: {}", selected);
                });

        if (!builder.registerModule()) {
            writeDiagnosticLine("[FAIL] Menu registration failed.");
            getSelf().getLogger().error("Menu registration failed.");
            return false;
        }

        writeDiagnosticLine("[OK] Menu registered.");

        const bool installed = installPlayerHook(getSelf());

        writeDiagnosticLine(std::string("[RESULT] Hook status: ") +
            (installed ? "SUCCESS" : "FAILED"));

        // Stay enabled even if the hook failed, so the menu and the
        // diagnostic file are still available.
        return true;
    }

    bool disable() {
        removePlayerHook(getSelf());
        pl::modmenu::unregisterModule(MODULE_ID);
        return !hookInstalled.load(std::memory_order_relaxed);
    }

    bool unload() {
        removePlayerHook(getSelf());
        pl::modmenu::unregisterModule(MODULE_ID);
        return !hookInstalled.load(std::memory_order_relaxed);
    }

private:
    ll::mod::NativeMod& self;
};

} // namespace

PL_REGISTER_MOD(TickRateController, TickRateController{});