


class INA219():
    def __init__(self, i2c_driver, i2c_addr=0x40, shunt_mOhm=100):
        self.i2c_addr = i2c_addr
        self.i2c = i2c_driver
        self.shunt = shunt_mOhm
        # config, +/-320mV, 68.10ms sample, continuous mode
        self.i2c.register_write(self.i2c_addr, 0x00, [0x3F, 0xFF])
    
    def get_voltage(self):
        v_reg = self.i2c.register_read(self.i2c_addr, 0x02, 2)
        voltage = int.from_bytes(v_reg, "big")
        voltage = (voltage >> 3) * 0.004
        return voltage
    
    def get_current(self):
        s_reg = self.i2c.register_read(self.i2c_addr, 0x01, 2)
        current = int.from_bytes(s_reg, "big", signed="True")
        current = current / 100 / self.shunt
        return current
