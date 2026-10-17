#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
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

class TickRateController {
public:
    bool load(pl::mod::ModContext& context) {
        auto& logger = context.logger();

        logger.info("TickRate Controller diagnostic build started.");

        // Try to create the mod's data directory.
        const auto dataDir = context.dataDir();
        std::error_code ec;
        std::filesystem::create_directories(dataDir, ec);

        const auto reportPath = dataDir / "diagnostic.txt";
        std::ofstream report(reportPath, std::ios::out | std::ios::trunc);

        if (!report) {
            logger.error(
                "Could not write diagnostic file: {}",
                reportPath.string());

            logger.error(
                "The mod data directory may not be writable.");

            return true;
        }

        report << "TickRate Controller diagnostic report\n";
        report << "Minecraft library: " << GAME_LIBRARY << "\n";

        const auto dimensionTick =
            pl::memory::resolveSignature(
                DIMENSION_TICK_SIGNATURE, GAME_LIBRARY);

        const auto normalTick =
            pl::memory::resolveSignature(
                NORMAL_TICK_SIGNATURE, GAME_LIBRARY);

        report << "DimensionTick: "
               << (dimensionTick ? "FOUND" : "NOT FOUND") << "\n";

        report << "NormalTick: "
               << (normalTick ? "FOUND" : "NOT FOUND") << "\n";

        report << "DimensionTick address: 0x"
               << std::hex << dimensionTick << "\n";

        report << "NormalTick address: 0x"
               << std::hex << normalTick << "\n";

        report << "\nNo hooks installed; simulation speed unchanged.\n";
        report.flush();

        logger.info("Diagnostic report written to: {}",
                    reportPath.string());

        return true;
    }

    bool enable() { return true; }
    bool disable() { return true; }
    bool unload() { return true; }
};

}

PL_REGISTER_MOD(TickRateController, TickRateController{});