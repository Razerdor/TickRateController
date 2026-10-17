#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/memory/Signature.hpp>

#include <string_view>

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
    bool load() {
        auto& logger =
            pl::log::Logger::getOrCreate("TickRateController");

        logger.info("TickRate Controller: diagnostic build started.");
        logger.info("Checking candidate Minecraft tick functions.");

        const auto dimensionTick =
            pl::memory::resolveSignature(
                DIMENSION_TICK_SIGNATURE, GAME_LIBRARY);

        const auto normalTick =
            pl::memory::resolveSignature(
                NORMAL_TICK_SIGNATURE, GAME_LIBRARY);

        logger.info(
            dimensionTick
                ? "DimensionTick signature FOUND."
                : "DimensionTick signature NOT FOUND.");

        logger.info(
            normalTick
                ? "NormalTick signature FOUND."
                : "NormalTick signature NOT FOUND.");

        logger.info(
            "Diagnostic only: simulation speed has not been changed.");

        return true;
    }

    bool enable() {
        return true;
    }

    bool disable() {
        return true;
    }

    bool unload() {
        return true;
    }
};

}

PL_REGISTER_MOD(TickRateController, TickRateController{});