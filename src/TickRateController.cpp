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

// Legacy values for 1.26.52.3. Only used as a tie-breaker / info now.
constexpr uintptr_t LEGACY_RVA = 0x0F9E26C0;
constexpr const char* EXPECTED_BUILD_ID =
    "56de9eed077631e03a31f4f58eb2f0e00071d335";

// Fingerprint of the function prologue found at 0xF9E26C0 in 1.26.52.3.
// All 8 instructions are position independent (no relative branches).
constexpr uint32_t SIGNATURE[] = {
    0xd100c3ff,  // sub sp, sp, #0x30
    0xa9017bfd,  // stp x29, x30, [sp, #0x10]
    0xa9024ff4,  // stp x20, x19, [sp, #0x20]
    0x910043fd,  // add x29, sp, #0x10
    0xd53bd054,  // mrs x20, TPIDR_EL0
    0xaa0003f3,  // mov x19, x0
    0xf9401688,  // ldr x8, [x20, #0x28]
    0xf90007e8,  // str x8, [sp, #0x8]
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

    if (diagnosticPath.empty()) {
        return;
    }

    std::ofstream out(diagnosticPath, std::ios::app);

    if (out) {
        out << line << '\n';
        out.flush();
    }
}

std::string pointerToHex(const void* ptr) {
    std::ostringstream out;

    out << "0x" << std::hex
        << reinterpret_cast<uintptr_t>(ptr);

    return out.str();
}

std::string numberToHex(uint64_t value) {
    std::ostringstream out;

    out << "0x" << std::hex << value;

    return out.str();
}

struct MinecraftLibraryInfo {
    uintptr_t base = 0;
    bool found = false;
    bool buildIdMatches = false;
    std::string buildId;

    // (runtime address, size in bytes) of executable segments.
    std::vector<std::pair<uintptr_t, size_t>> execSegments;
};

int inspectMinecraftLibrary(
    dl_phdr_info* info,
    size_t,
    void* userData
) {
    if (
        !info ||
        !info->dlpi_name ||
        !userData ||
        !std::strstr(info->dlpi_name, "libminecraftpe.so")
    ) {
        return 0;
    }

    auto* result =
        static_cast<MinecraftLibraryInfo*>(userData);

    result->base = static_cast<uintptr_t>(info->dlpi_addr);
    result->found = true;

    // Collect executable load segments for the signature scan.
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const auto& phdr = info->dlpi_phdr[i];

        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            result->execSegments.emplace_back(
                static_cast<uintptr_t>(
                    info->dlpi_addr + phdr.p_vaddr
                ),
                static_cast<size_t>(phdr.p_filesz)
            );
        }
    }

    // Read the GNU build ID (informational only).
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const auto& phdr = info->dlpi_phdr[i];

        if (phdr.p_type != PT_NOTE) {
            continue;
        }

        auto* note = reinterpret_cast<const unsigned char*>(
            info->dlpi_addr + phdr.p_vaddr
        );

        size_t remaining = phdr.p_memsz;

        while (remaining >= sizeof(ElfW(Nhdr))) {
            ElfW(Nhdr) header{};

            std::memcpy(&header, note, sizeof(header));

            const size_t nameSize =
                (header.n_namesz + 3u) & ~size_t(3u);

            const size_t descSize =
                (header.n_descsz + 3u) & ~size_t(3u);

            const size_t totalSize =
                sizeof(ElfW(Nhdr)) + nameSize + descSize;

            if (totalSize > remaining) {
                break;
            }

            const unsigned char* name =
                note + sizeof(ElfW(Nhdr));

            const unsigned char* desc =
                name + nameSize;

            if (
                header.n_type == NT_GNU_BUILD_ID &&
                header.n_namesz == 4 &&
                std::memcmp(name, "GNU", 3) == 0
            ) {
                static constexpr char hexDigits[] =
                    "0123456789abcdef";

                char buildId[65]{};

                const size_t byteCount =
                    header.n_descsz < 32
                        ? header.n_descsz
                        : 32;

                for (size_t j = 0; j < byteCount; ++j) {
                    buildId[j * 2] =
                        hexDigits[(desc[j] >> 4) & 0x0F];

                    buildId[j * 2 + 1] =
                        hexDigits[desc[j] & 0x0F];
                }

                result->buildId = buildId;

                result->buildIdMatches =
                    std::string_view(buildId) ==
                    EXPECTED_BUILD_ID;

                return 1;
            }

            note += totalSize;
            remaining -= totalSize;
        }
    }

    return 1;
}

// Scans the loaded executable segments for SIGNATURE.
// Returns RVAs (offset from library base) of every match, max 16.
std::vector<uintptr_t> scanForSignature(
    const MinecraftLibraryInfo& library
) {
    std::vector<uintptr_t> hits;

    for (const auto& segment : library.execSegments) {
        const auto* words =
            reinterpret_cast<const uint32_t*>(segment.first);

        const size_t count = segment.second / sizeof(uint32_t);

        if (count < SIGNATURE_WORDS) {
            continue;
        }

        for (size_t i = 0; i + SIGNATURE_WORDS <= count; ++i) {
            if (words[i] != SIGNATURE[0]) {
                continue;
            }

            if (std::memcmp(
                    words + i,
                    SIGNATURE,
                    sizeof(SIGNATURE)
                ) == 0) {
                hits.push_back(
                    segment.first +
                    i * sizeof(uint32_t) -
                    library.base
                );

                if (hits.size() >= 16) {
                    return hits;
                }
            }
        }
    }

    return hits;
}

// Radio callback values are expected to be indices:
//
// 0 = 20 TPS
// 1 = 15 TPS
// 2 = 10 TPS
// 3 = 5 TPS
// 4 = Reset to 20 TPS
//
// Literal labels are also accepted for compatibility.
bool parseTpsOption(
    std::string_view value,
    int& selected
) {
    if (value == "0") {
        selected = 20;
    } else if (value == "1") {
        selected = 15;
    } else if (value == "2") {
        selected = 10;
    } else if (value == "3") {
        selected = 5;
    } else if (value == "4") {
        selected = 20;
    } else if (value == "20" || value == "20 TPS") {
        selected = 20;
    } else if (value == "15" || value == "15 TPS") {
        selected = 15;
    } else if (value == "10" || value == "10 TPS") {
        selected = 10;
    } else if (value == "5" || value == "5 TPS") {
        selected = 5;
    } else if (
        value == "Reset" ||
        value == "Reset (20 TPS)"
    ) {
        selected = 20;
    } else {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------
// DIAGNOSTIC: once-per-second rate reporter.
// ---------------------------------------------------------------
std::atomic<void*> lastSelf{nullptr};
std::atomic<uint64_t> selfChanges{0};
std::atomic_bool reporterRun{false};
std::thread reporterThread;

void startReporter() {
    if (reporterRun.exchange(true)) {
        return;
    }

    reporterThread = std::thread([] {
        uint64_t lastD = 0;
        uint64_t lastO = 0;
        uint64_t lastS = 0;

        while (reporterRun.load()) {
            std::this_thread::sleep_for(
                std::chrono::seconds(1)
            );

            if (!reporterRun.load()) {
                break;
            }

            const uint64_t d = detourCalls.load();
            const uint64_t o = originalCalls.load();
            const uint64_t s = selfChanges.load();

            writeDiagnosticLine(
                "[RATE] tps=" +
                std::to_string(targetTps.load()) +
                " detour/s=" + std::to_string(d - lastD) +
                " original/s=" + std::to_string(o - lastO) +
                " selfChanges/s=" + std::to_string(s - lastS) +
                " lastSelf=" + pointerToHex(lastSelf.load())
            );

            lastD = d;
            lastO = o;
            lastS = s;
        }
    });
}

void stopReporter() {
    reporterRun.store(false);

    if (reporterThread.joinable()) {
        reporterThread.join();
    }
}

void playerNormalTickDetour(void* self) {
    detourCalls.fetch_add(1, std::memory_order_relaxed);

    // DIAGNOSTIC: track whether `self` changes between calls.
    if (lastSelf.exchange(self, std::memory_order_relaxed) != self) {
        selfChanges.fetch_add(1, std::memory_order_relaxed);
    }

    void* original = originalPlayerNormalTick;

    if (!original) {
        return;
    }

    const int tps = targetTps.load(
        std::memory_order_relaxed
    );

    if (tps >= 20 || tps <= 0) {
        tickPhase.store(0, std::memory_order_relaxed);

        reinterpret_cast<void (*)(void*)>(
            original
        )(self);

        originalCalls.fetch_add(
            1,
            std::memory_order_relaxed
        );

        return;
    }

    // Experimental player-only throttling.
    // This does not control the entire Minecraft world tick.

    int phase = tickPhase.load(std::memory_order_relaxed);

    for (;;) {
        int next = phase + tps;
        const bool shouldRun = next >= 20;

        if (shouldRun) {
            next -= 20;
        }

        if (tickPhase.compare_exchange_weak(
                phase,
                next,
                std::memory_order_relaxed,
                std::memory_order_relaxed
            )) {
            if (!shouldRun) {
                return;
            }

            break;
        }
    }

    reinterpret_cast<void (*)(void*)>(
        original
    )(self);

    originalCalls.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

bool installPlayerHook(ll::mod::NativeMod& mod) {
    auto& logger = mod.getLogger();

    writeDiagnosticLine(
        "[CHECK] Hook installation started."
    );

    if (hookInstalled.load(std::memory_order_relaxed)) {
        writeDiagnosticLine(
            "[INFO] Hook was already installed."
        );

        return true;
    }

    MinecraftLibraryInfo library{};

    dl_iterate_phdr(
        inspectMinecraftLibrary,
        &library
    );

    if (!library.found) {
        writeDiagnosticLine(
            "[FAIL] Minecraft library not found."
        );

        logger.error(
            "TickRate Controller: Minecraft library not found."
        );

        return false;
    }

    writeDiagnosticLine(
        "[OK] Minecraft library found. Base=" +
        pointerToHex(
            reinterpret_cast<void*>(library.base)
        )
    );

    writeDiagnosticLine(
        "[INFO] Build ID (running game)=" + library.buildId
    );

    writeDiagnosticLine(
        std::string("[INFO] Build ID matches 1.26.52.3: ") +
        (library.buildIdMatches ? "YES" : "NO") +
        " (no longer blocks the hook)"
    );

    writeDiagnosticLine(
        "[INFO] Executable segments=" +
        std::to_string(library.execSegments.size())
    );

    // ---- Runtime signature scan ----
    const std::vector<uintptr_t> hits =
        scanForSignature(library);

    writeDiagnosticLine(
        "[SCAN] Signature hits=" + std::to_string(hits.size())
    );

    for (uintptr_t rva : hits) {
        uint32_t next[8]{};

        std::memcpy(
            next,
            reinterpret_cast<const void*>(
                library.base + rva + sizeof(SIGNATURE)
            ),
            sizeof(next)
        );

        std::ostringstream line;

        line << "[SCAN] hit RVA=" << numberToHex(rva)
             << " next words:" << std::hex;

        for (uint32_t w : next) {
            line << ' ' << w;
        }

        writeDiagnosticLine(line.str());
    }

    uintptr_t chosenRva = 0;
    bool haveTarget = false;

    if (library.buildIdMatches) {
        for (uintptr_t rva : hits) {
            if (rva == LEGACY_RVA) {
                chosenRva = rva;
                haveTarget = true;
                break;
            }
        }
    }

    if (!haveTarget && hits.size() == 1) {
        chosenRva = hits[0];
        haveTarget = true;
    }

    if (!haveTarget) {
        writeDiagnosticLine(
            hits.empty()
                ? "[FAIL] Signature not found in this build. Hook skipped."
                : "[FAIL] Multiple signature hits; refusing to guess. "
                  "Hook skipped."
        );

        logger.error(
            "TickRate Controller: could not resolve player tick."
        );

        return false;
    }

    writeDiagnosticLine(
        "[SCAN] Chosen RVA=" + numberToHex(chosenRva)
    );

    playerNormalTickAddress = reinterpret_cast<void*>(
        library.base + chosenRva
    );

    writeDiagnosticLine(
        "[CHECK] Hook target=" +
        pointerToHex(playerNormalTickAddress)
    );

    const int result = pl::memory::hook(
        playerNormalTickAddress,
        reinterpret_cast<void*>(&playerNormalTickDetour),
        &originalPlayerNormalTick
    );

    writeDiagnosticLine(
        "[CHECK] Hook return code=" +
        std::to_string(result)
    );

    writeDiagnosticLine(
        "[CHECK] Original function pointer=" +
        pointerToHex(originalPlayerNormalTick)
    );

    if (result != 0 || !originalPlayerNormalTick) {
        writeDiagnosticLine(
            "[FAIL] Hook installation failed or original pointer is null."
        );

        logger.error(
            "TickRate Controller: Player tick hook failed."
        );

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

    // DIAGNOSTIC: start once-per-second [RATE] logging.
    startReporter();

    writeDiagnosticLine(
        "[OK] Hook installation succeeded."
    );

    logger.info(
        "TickRate Controller: experimental player-tick hook installed."
    );

    return true;
}

void removePlayerHook(ll::mod::NativeMod& mod) {
    if (!hookInstalled.load(std::memory_order_relaxed)) {
        return;
    }

    // DIAGNOSTIC: stop the reporter before unhooking.
    stopReporter();

    const bool removed = pl::memory::unhook(
        playerNormalTickAddress,
        reinterpret_cast<void*>(&playerNormalTickDetour)
    );

    if (removed) {
        writeDiagnosticLine(
            "[INFO] Hook removed successfully."
        );

        hookInstalled.store(false, std::memory_order_relaxed);

        playerNormalTickAddress = nullptr;
        originalPlayerNormalTick = nullptr;

        tickPhase.store(0, std::memory_order_relaxed);

        mod.getLogger().info(
            "TickRate Controller: player-tick hook removed."
        );
    } else {
        writeDiagnosticLine(
            "[FAIL] Hook removal failed."
        );

        mod.getLogger().error(
            "TickRate Controller: failed to remove player-tick hook."
        );
    }
}

class TickRateController {
public:
    TickRateController()
        : self(*ll::mod::NativeMod::current()) {}

    ll::mod::NativeMod& getSelf() const {
        return self;
    }

    bool load() {
        diagnosticPath =
            getSelf().getDataDir() / "diagnostic.txt";

        std::error_code ec;

        std::filesystem::create_directories(
            diagnosticPath.parent_path(),
            ec
        );

        {
            std::lock_guard<std::mutex> lock(diagnosticMutex);

            std::ofstream out(
                diagnosticPath,
                std::ios::trunc
            );

            if (out) {
                out << "=== TickRateController Diagnostics ===\n";
                out << "Build: runtime signature scan (version independent)\n";

                out << "Legacy Build ID (1.26.52.3): "
                    << EXPECTED_BUILD_ID << '\n';

                out << "Legacy RVA: 0xF9E26C0\n";

                out << "Radio mapping: "
                    << "0=20, 1=15, 2=10, 3=5, 4=Reset/20\n";

                out << "Scope: player normalTick only; "
                    << "not full-world TPS\n";

                out << "Mod load stage: OK\n";

                out.flush();
            }
        }

        if (ec) {
            getSelf().getLogger().error(
                "Diagnostic directory creation failed: {}",
                ec.message()
            );
        }

        std::error_code existsError;

        writeDiagnosticLine(
            std::filesystem::exists(
                diagnosticPath,
                existsError
            )
                ? "[OK] Diagnostic file created."
                : "[FAIL] Diagnostic file could not be created."
        );

        getSelf().getLogger().info(
            "TickRate Controller loaded."
        );

        return true;
    }

    bool enable() {
        pl::modmenu::ModuleBuilder builder(
            MODULE_ID,
            "TickRate Controller"
        );

        builder
            .modId(getSelf().getId())
            .description(
                "Experimental player-tick throttling only. "
                "Does not change full-world or server TPS."
            )
            .defaultEnabled(true)

            // Radio values are option indices, not the displayed labels.
            .config(
                "target_tps",
                "Target TPS",
                pl::modmenu::ConfigType::Radio,
                "0",
                "20 TPS,15 TPS,10 TPS,5 TPS,Reset (20 TPS)"
            )

            .onConfigChanged(
                [this](
                    std::string_view moduleId,
                    std::string_view key,
                    std::string_view value
                ) {
                    if (
                        moduleId != MODULE_ID ||
                        key != "target_tps"
                    ) {
                        return;
                    }

                    writeDiagnosticLine(
                        "[CONFIG] Raw radio value=[" +
                        std::string(value) + "]"
                    );

                    int selected = 20;

                    if (!parseTpsOption(value, selected)) {
                        writeDiagnosticLine(
                            "[WARN] Unknown TPS option value=[" +
                            std::string(value) + "]"
                        );

                        return;
                    }

                    targetTps.store(
                        selected,
                        std::memory_order_relaxed
                    );

                    tickPhase.store(
                        0,
                        std::memory_order_relaxed
                    );

                    writeDiagnosticLine(
                        "[CONFIG] Selected TPS=" +
                        std::to_string(selected)
                    );

                    writeDiagnosticLine(
                        std::st