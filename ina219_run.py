#!/usr/bin/env python3


import time
import os
import ina219
import ch341


i2c_driver = ch341.CH341()
i2c_driver.set_speed(400)

ina1 = ina219.INA219(i2c_driver, 0x40, 50)
    
while True:
    voltage = ina1.get_voltage()
    print("voltage %.2f V" % round(voltage, 2))
    
    current = ina1.get_current()
    print("current %.3f A" % round(current, 3))
    print("power   %.3f W" % round(voltage*current, 3))
    time.sleep(0.5)
    os.system('clear')
