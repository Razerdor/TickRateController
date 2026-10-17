#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/ModMenu.hpp>
#include <pl/memory/Signature.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

namespace {

constexpr std::string_view DIMENSION_TICK_SIGNATURE =
    "? ? ? D1 ? ? ? FD ? ? ? 6D ? ? ? 6D ? ? ? A9 "
    "? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 "
    "? ? ? 91 5C D0 3B D5 1F 20 03 D5";

constexpr std::string_view NORMAL_TICK_SIGNATURE =
    "? ? ? FC ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 "
    "? ? ? A9 ? ? ? A9 ? ? ? 91 ? ? ? D1 54 D0 3B D5 "
    "F3 03 00 AA ? ? ? F9 ? ? ? F8 ? ? ? 39";

constexpr std::string_view GAME_LIBRARY = "libminecraftpe.so";
constexpr std::string_view MODULE_ID = "tickrate_controller";

int selectedTPS = 20;
bool moduleRegistered = false;

void selectTPS(std::string_view value) {
    if (value == "20") {
        selectedTPS = 20;
    } else if (value == "15") {
        selectedTPS = 15;
    } else if (value == "10") {
        selectedTPS = 10;
    } else if (value == "5") {
        selectedTPS = 5;
    } else if (value == "reset") {
        selectedTPS = 20;
    }
}

class TickRateController {
public:
    bool load(pl::mod::ModContext& context) {
        auto& logger = context.logger();

        logger.info("TickRate Controller loading.");

        pl::modmenu::ModuleInfo info{};
        info.moduleId = MODULE_ID;
        info.displayName = "TickRate Controller";
        info.description =
            "Select a target simulation rate. Actual tick control is not implemented yet.";
        info.modId = "tickrate_controller";
        info.defaultEnabled = true;

        info.configs.push_back({
            .key = "target_tps",
            .displayName = "Target TPS",
            .type = pl::modmenu::ConfigType::Radio,
            .defaultValue = "20",
        });

        info.onConfigChanged =
            [](std::string_view, std::string_view key,
               std::string_view value) {
                if (key == "target_tps") {
                    selectTPS(value);
                }
            };

        moduleRegistered = pl::modmenu::registerModule(info);

        if (!moduleRegistered) {
            logger.error("Could not register TickRate Controller menu.");
        } else {
            logger.info("TickRate Controller menu registered.");
        }

        std::error_code ec;
        const auto dataDir = context.dataDir();
        std::filesystem::create_directories(dataDir, ec);

        std::ofstream report(
            dataDir / "diagnostic.txt",
            std::ios::out | std::ios::trunc);

        if (report) {
            const auto dimensionTick =
                pl::memory::resolveSignature(
                    DIMENSION_TICK_SIGNATURE, GAME_LIBRARY);

            const auto normalTick =
                pl::memory::resolveSignature(
                    NORMAL_TICK_SIGNATURE, GAME_LIBRARY);

            report << "TickRate Controller\n";
            report << "DimensionTick: "
                   << (dimensionTick ? "FOUND" : "NOT FOUND") << "\n";
            report << "NormalTick: "
                   << (normalTick ? "FOUND" : "NOT FOUND") << "\n";
            report << "Selected target TPS: " << selectedTPS << "\n";
            report << "Global tick hook: NOT IMPLEMENTED\n";
            report << "Actual simulation speed: UNCHANGED\n";
        }

        return true;
    }

    bool enable() {
        return true;
    }

    bool disable() {
        return true;
    }

    bool unload() {
        if (moduleRegistered) {
            pl::modmenu::unregisterModule(MODULE_ID);
            moduleRegistered = false;
        }

        return true;
    }
};

}

PL_REGISTER_MOD(TickRateController, TickRateController{});