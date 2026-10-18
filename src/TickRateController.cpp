#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/ModMenu.hpp>

#include <atomic>
#include <string>
#include <string_view>

namespace {

constexpr const char* MODULE_ID = "tickrate_controller";

std::atomic<int> targetTps{20};

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
                "Select a target TPS for Minecraft."
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
                            "Unknown TPS option selected."
                        );
                        return;
                    }

                    targetTps.store(
                        selected,
                        std::memory_order_relaxed
                    );

                    getSelf().getLogger().info(
                        "Selected target: {} TPS.",
                        selected
                    );
                }
            );

        const bool registered =
            builder.registerModule();

        if (registered) {
            getSelf().getLogger().info(
                "TickRate Controller menu registered."
            );
        } else {
            getSelf().getLogger().error(
                "TickRate Controller menu registration failed."
            );
        }

        return registered;
    }

    bool disable() {
        pl::modmenu::unregisterModule(MODULE_ID);
        return true;
    }

    bool unload() {
        pl::modmenu::unregisterModule(MODULE_ID);
        return true;
    }

private:
    ll::mod::NativeMod& self;
};

}

PL_REGISTER_MOD(TickRateController, TickRateController{});