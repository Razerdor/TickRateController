#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/ModMenu.hpp>
#include <pl/memory/Hook.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <link.h>
#include <elf.h>

namespace {

constexpr const char* MODULE_ID = "tickrate_controller";

constexpr uintptr_t PLAYER_NORMAL_TICK_RVA = 0x0F9E26C0;

constexpr const char* EXPECTED_BUILD_ID =
    "56de9eed077631e03a31f4f58eb2f0e00071d335";

std::atomic<int> targetTps{20};

std::atomic<uint64_t> detourCalls{0};
std::atomic<uint64_t> originalCalls{0};

void* originalPlayerNormalTick = nullptr;
void* playerNormalTickAddress = nullptr;

bool hookInstalled = false;
int tickPhase = 0;

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

struct MinecraftLibraryInfo {
    uintptr_t base = 0;
    bool found = false;
    bool buildIdMatches = false;
};

int inspectMinecraftLibrary(
    dl_phdr_info* info,
    size_t,
    void* userData
) {
    if (!info || !info->dlpi_name || !userData) {
        return 0;
    }

    if (!std::strstr(info->dlpi_name, "libminecraftpe.so")) {
        return 0;
    }

    auto* result =
        static_cast<MinecraftLibraryInfo*>(userData);

    result->base = static_cast<uintptr_t>(info->dlpi_addr);
    result->found = true;

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

void playerNormalTickDetour(void* self) {
    detourCalls.fetch_add(1, std::memory_order_relaxed);

    if (!originalPlayerNormalTick) {
        return;
    }

    const int tps = targetTps.load(
        std::memory_order_relaxed
    );

    if (tps >= 20 || tps <= 0) {
        tickPhase = 0;

        reinterpret_cast<void (*)(void*)>(
            originalPlayerNormalTick
        )(self);

        originalCalls.fetch_add(
            1, std::memory_order_relaxed
        );

        return;
    }

    // Experimental player-tick throttling.
    tickPhase += tps;

    if (tickPhase < 20) {
        return;
    }

    tickPhase -= 20;

    reinterpret_cast<void (*)(void*)>(
        originalPlayerNormalTick
    )(self);

    originalCalls.fetch_add(
        1, std::memory_order_relaxed
    );
}

bool installPlayerHook(ll::mod::NativeMod& mod) {
    auto& logger = mod.getLogger();

    writeDiagnosticLine("[CHECK] Hook installation started.");

    if (hookInstalled) {
        writeDiagnosticLine("[INFO] Hook was already installed.");
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
        pointerToHex(reinterpret_cast<void*>(library.base))
    );

    writeDiagnosticLine(
        std::string("[CHECK] Build ID matches: ") +
        (library.buildIdMatches ? "YES" : "NO")
    );

    if (!library.buildIdMatches) {
        writeDiagnosticLine(
            "[FAIL] Build ID mismatch. Hook skipped."
        );

        logger.error(
            "TickRate Controller: Build ID mismatch."
        );

        return false;
    }

    playerNormalTickAddress = reinterpret_cast<void*>(
        library.base + PLAYER_NORMAL_TICK_RVA
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

    hookInstalled = true;
    tickPhase = 0;

    detourCalls.store(0, std::memory_order_relaxed);
    originalCalls.store(0, std::memory_order_relaxed);

    writeDiagnosticLine(
        "[OK] Hook installation succeeded."
    );

    logger.info(
        "TickRate Controller: experimental player-tick hook installed."
    );

    return true;
}

void removePlayerHook(ll::mod::NativeMod& mod) {
    if (!hookInstalled) {
        return;
    }

    const bool removed = pl::memory::unhook(
        playerNormalTickAddress,
        reinterpret_cast<void*>(&playerNormalTickDetour)
    );

    if (removed) {
        writeDiagnosticLine("[INFO] Hook removed successfully.");

        hookInstalled = false;
        playerNormalTickAddress = nullptr;
        originalPlayerNormalTick = nullptr;
        tickPhase = 0;

        mod.getLogger().info(
            "TickRate Controller: player-tick hook removed."
        );
    } else {
        writeDiagnosticLine("[FAIL] Hook removal failed.");

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
                out << "Expected Minecraft version: 1.26.52.3\n";
                out << "Expected Build ID: "
                    << EXPECTED_BUILD_ID << '\n';
                out << "Hook RVA: 0xF9E26C0\n";
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
                "Experimental player-tick throttling. "
                "Does not change full-world TPS."
            )
            .defaultEnabled(true)
            .config(
                "target_tps",
                "Target TPS",
                pl::modmenu::ConfigType::Radio,
                "20",
                "20,15,10,5,Reset"
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

                    int selected = 20;

                    if (value == "15") {
                        selected = 15;
                    } else if (value == "10") {
                        selected = 10;
                    } else if (value == "5") {
                        selected = 5;
                    } else if (
                        value != "20" &&
                        value != "Reset"
                    ) {
                        writeDiagnosticLine(
                            "[WARN] Unknown TPS option received."
                        );

                        return;
                    }

                    targetTps.store(
                        selected,
                        std::memory_order_relaxed
                    );

                    writeDiagnosticLine(
                        "[CONFIG] Selected TPS=" +
                        std::to_string(selected)
                    );

                    writeDiagnosticLine(
                        std::string("[STATUS] Hook installed: ") +
                        (hookInstalled ? "YES" : "NO")
                    );

                    writeDiagnosticLine(
                        "[RUNTIME SNAPSHOT] Detour calls=" +
                        std::to_string(
                            detourCalls.load(
                                std::memory_order_relaxed
                            )
                        ) +
                        ", original calls=" +
                        std::to_string(
                            originalCalls.load(
                                std::memory_order_relaxed
                            )
                        )
                    );

                    getSelf().getLogger().info(
                        "Selected experimental player tick rate: {}",
                        selected
                    );
                }
            );

        if (!builder.registerModule()) {
            writeDiagnosticLine(
                "[FAIL] Menu registration failed."
            );

            getSelf().getLogger().error(
                "TickRate Controller menu registration failed."
            );

            return false;
        }

        writeDiagnosticLine("[OK] Menu registered.");

        getSelf().getLogger().info(
            "TickRate Controller menu registered."
        );

        const bool installed = installPlayerHook(getSelf());

        writeDiagnosticLine(
            std::string("[RESULT] Hook status: ") +
            (installed ? "SUCCESS" : "FAILED")
        );

        return installed;
    }

    bool disable() {
        removePlayerHook(getSelf());

        pl::modmenu::unregisterModule(MODULE_ID);

        return !hookInstalled;
    }

    bool unload() {
        removePlayerHook(getSelf());

        pl::modmenu::unregisterModule(MODULE_ID);

        return !hookInstalled;
    }

private:
    ll::mod::NativeMod& self;
};

}

PL_REGISTER_MOD(TickRateController, TickRateController{});