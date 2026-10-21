#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/ModMenu.hpp>
#include <pl/memory/Hook.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <link.h>
#include <elf.h>
#include <string_view>

namespace {

constexpr const char* MODULE_ID = "tickrate_controller";

// Reference RVA for Minecraft Bedrock 1.26.52.3 ARM64.
// Must be verified against the actual loaded binary.
constexpr uintptr_t PLAYER_NORMAL_TICK_RVA = 0x0F9E26C0;

// Build ID reported for the target Minecraft library.
constexpr const char* EXPECTED_BUILD_ID =
    "56de9eed077631e03a31f4f58eb2f0e00071d335";

std::atomic<int> targetTps{20};

void* originalPlayerNormalTick = nullptr;
void* playerNormalTickAddress = nullptr;

bool hookInstalled = false;

// The prototype throttles calls to Player::normalTick.
// It does NOT change the global Minecraft world tick rate.
int tickPhase = 0;

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

        return;
    }

    // Approximate the requested fraction of normal calls:
    // 15 TPS -> 3 of every 4 calls
    // 10 TPS -> 1 of every 2 calls
    //  5 TPS -> 1 of every 4 calls
    tickPhase += tps;

    if (tickPhase < 20) {
        return;
    }

    tickPhase -= 20;

    reinterpret_cast<void (*)(void*)>(
        originalPlayerNormalTick
    )(self);
}

bool installPlayerHook(
    ll::mod::NativeMod& mod
) {
    auto& logger = mod.getLogger();

    if (hookInstalled) {
        return true;
    }

    MinecraftLibraryInfo library{};

    dl_iterate_phdr(
        inspectMinecraftLibrary,
        &library
    );

    if (!library.found) {
        logger.error(
            "TickRate Controller: Minecraft library not found."
        );
        return false;
    }

    if (!library.buildIdMatches) {
        logger.error(
            "TickRate Controller: Build ID mismatch; "
            "refusing to install experimental hook."
        );
        return false;
    }

    playerNormalTickAddress = reinterpret_cast<void*>(
        library.base + PLAYER_NORMAL_TICK_RVA
    );

    const int result = pl::memory::hook(
        playerNormalTickAddress,
        reinterpret_cast<void*>(&playerNormalTickDetour),
        &originalPlayerNormalTick
    );

    if (result != 0 || !originalPlayerNormalTick) {
        logger.error(
            "TickRate Controller: Player tick hook failed."
        );

        playerNormalTickAddress = nullptr;
        originalPlayerNormalTick = nullptr;
        return false;
    }

    hookInstalled = true;
    tickPhase = 0;

    logger.info(
        "TickRate Controller: experimental player-tick "
        "hook installed."
    );

    return true;
}

void removePlayerHook(
    ll::mod::NativeMod& mod
) {
    if (!hookInstalled) {
        return;
    }

    const bool removed = pl::memory::unhook(
        playerNormalTickAddress,
        reinterpret_cast<void*>(&playerNormalTickDetour)
    );

    if (removed) {
        hookInstalled = false;
        playerNormalTickAddress = nullptr;
        originalPlayerNormalTick = nullptr;
        tickPhase = 0;

        mod.getLogger().info(
            "TickRate Controller: player-tick hook removed."
        );
    } else {
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
                "Does not change the full world tick rate."
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
                        getSelf().getLogger().warn(
                            "Unknown TPS option."
                        );
                        return;
                    }

                    targetTps.store(
                        selected,
                        std::memory_order_relaxed
                    );

                    getSelf().getLogger().info(
                        "Selected experimental player tick rate: {}",
                        selected
                    );
                }
            );

        if (!builder.registerModule()) {
            getSelf().getLogger().error(
                "TickRate Controller menu registration failed."
            );
            return false;
        }

        getSelf().getLogger().info(
            "TickRate Controller menu registered."
        );

        // Do not silently report success if the hook failed.
        return installPlayerHook(getSelf());
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