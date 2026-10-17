#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/memory/Signature.hpp>

#include <filesystem>
#include <fstream>
#include <iomanip>
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

enum class SpeedMode {
    Normal,
    TPS15,
    TPS10,
    TPS5
};

class TickRateController {
private:
    SpeedMode mode = SpeedMode::Normal;

    static int targetTPS(SpeedMode selected) {
        switch (selected) {
            case SpeedMode::TPS15: return 15;
            case SpeedMode::TPS10: return 10;
            case SpeedMode::TPS5:  return 5;
            case SpeedMode::Normal:
            default:               return 20;
        }
    }

public:
    bool load(pl::mod::ModContext& context) {
        auto& logger = context.logger();

        logger.info("TickRate Controller loading.");

        std::error_code ec;
        const auto dataDir = context.dataDir();

        std::filesystem::create_directories(dataDir, ec);

        const auto reportPath = dataDir / "diagnostic.txt";
        std::ofstream report(reportPath, std::ios::out | std::ios::trunc);

        if (!report) {
            logger.error("Could not write diagnostic report.");
            return true;
        }

        const auto dimensionTick =
            pl::memory::resolveSignature(
                DIMENSION_TICK_SIGNATURE, GAME_LIBRARY);

        const auto normalTick =
            pl::memory::resolveSignature(
                NORMAL_TICK_SIGNATURE, GAME_LIBRARY);

        report << "TickRate Controller\n";
        report << "Minecraft library: " << GAME_LIBRARY << "\n";

        report << "DimensionTick signature: "
               << (dimensionTick ? "FOUND" : "NOT FOUND") << "\n";

        report << "NormalTick signature: "
               << (normalTick ? "FOUND" : "NOT FOUND") << "\n";

        report << "Selected target TPS: "
               << targetTPS(mode) << "\n";

        report << "Global tick hook: NOT IMPLEMENTED\n";
        report << "Actual simulation speed: UNCHANGED\n";

        report.flush();

        logger.info(
            "TickRate Controller loaded. Target: {} TPS; "
            "global tick control is not implemented.",
            targetTPS(mode));

        return true;
    }

    bool enable() {
        return true;
    }

    bool disable() {
        // No hooks have been installed, so nothing needs unhooking.
        return true;
    }

    bool unload() {
        return true;
    }
};

}

PL_REGISTER_MOD(TickRateController, TickRateController{});