import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID

CONF_UPDATE_INTERVAL = "update_interval"

aqara_fp2_accel_ns = cg.esphome_ns.namespace("aqara_fp2_accel")
AqaraFP2Accel = aqara_fp2_accel_ns.class_(
    "AqaraFP2Accel", cg.Component
)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(AqaraFP2Accel),
        cv.Optional(CONF_UPDATE_INTERVAL, default="100ms"): cv.positive_time_period_milliseconds,
    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    # Set update interval in milliseconds
    cg.add(var.set_update_interval(config[CONF_UPDATE_INTERVAL].total_milliseconds))
