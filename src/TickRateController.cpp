#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <pl/ModMenu.hpp>

#include <string>
#include <string_view>

namespace {

constexpr const char* MODULE_ID = "tickrate_controller";

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
                "TickRate Controller menu test."
            )
            .defaultEnabled(true)
            .config(
                "target_tps",
                "Target TPS",
                pl::modmenu::ConfigType::Radio,
                "20",
                "20,15,10,5,Reset"
            );

        const bool registered = builder.registerModule();

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