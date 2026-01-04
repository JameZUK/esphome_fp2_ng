import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import binary_sensor
from esphome.const import (
    CONF_ID,
    CONF_TYPE,
    DEVICE_CLASS_MOTION,
    DEVICE_CLASS_OCCUPANCY,
)

from . import CONF_FP2_ID, FP2Component, FP2Zone, aqara_fp2_ns

CONF_ZONE_ID = "zone_id"

FP2ZoneBinarySensor = aqara_fp2_ns.class_(
    "FP2ZoneBinarySensor", binary_sensor.BinarySensor, cg.Component
)

FP2ZoneSensorType = aqara_fp2_ns.enum("FP2ZoneSensorType", is_class=True)
SENSOR_TYPES = {
    "presence": FP2ZoneSensorType.PRESENCE,
    "motion": FP2ZoneSensorType.MOTION,
}

CONFIG_SCHEMA = cv.typed_schema(
    {
        "presence": binary_sensor.binary_sensor_schema(
            FP2ZoneBinarySensor,
            device_class=DEVICE_CLASS_OCCUPANCY,
        )
        .extend(
            {
                cv.Required(CONF_ZONE_ID): cv.use_id(FP2Zone),
            }
        )
        .extend(cv.COMPONENT_SCHEMA),
        "motion": binary_sensor.binary_sensor_schema(
            FP2ZoneBinarySensor,
            device_class=DEVICE_CLASS_MOTION,
        )
        .extend(
            {
                cv.Required(CONF_ZONE_ID): cv.use_id(FP2Zone),
            }
        )
        .extend(cv.COMPONENT_SCHEMA),
    },
    lower=True,
)


async def to_code(config):
    var = await binary_sensor.new_binary_sensor(config)
    await cg.register_component(var, config)

    zone = await cg.get_variable(config[CONF_ZONE_ID])
    cg.add(var.set_zone(zone))

    cg.add(var.set_sensor_type(SENSOR_TYPES[config[CONF_TYPE]]))
