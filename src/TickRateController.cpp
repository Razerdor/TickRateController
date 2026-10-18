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
        self.getLogger().info("TickRate Controller loaded.");
        return true;
    }

    bool enable() {
        const bool registered =
            pl::modmenu::ModuleBuilder(
                MODULE_ID, "TickRate Controller")
                .modId(getSelf().getId())
                .description(
                    "Menu registration test. "
                    "Global tick control is not implemented.")
                .defaultEnabled(true)
                .config(
                    "target_tps",
                    "Target TPS",
                    pl::modmenu::ConfigType::Radio,
                    "0",
                    "20,15,10,5,Reset")
                .onConfigChanged(
                    [](std::string_view,
                       std::string_view key,
                       std::string_view value) {
                        if (key == "target_tps") {
                            getSelfLogger(value);
                        }
                    })
                .registerModule();

        if (registered) {
            getSelf().getLogger().info(
                "TickRate Controller menu registered.");
        } else {
            getSelf().getLogger().error(
                "TickRate Controller menu registration failed.");
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

    static void getSelfLogger(std::string_view value) {
        (void)value;
    }
};

}

PL_REGISTER_MOD(TickRateController, TickRateController{});