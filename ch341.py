#!/usr/bin/env python
# This code based on https://github.com/karlp/ch341-py2c
# and https://github.com/gschorcht/i2c-ch341-usb
# 
# author:
# Karl Palsson, October 2014 <karlp@tweak.net.au>
# Considered to be released under your choice of MIT/Apache2/BSD 2 clause
#
# Provides generic hooks for reading/writing i2c via a CH341 in i2c/mem/epp
# mode.  Has only been _currently_ tested with a CH341A device.
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("py2c-ch34x")

import struct
import usb.core

class CtrlCommands():
    """
    This is just usb standard stuff...
    """
    WRITE_TYPE = 0x40
    READ_TYPE = 0xc0

class VendorCommands():
    READ_REG = 0x95
    WRITE_REG = 0x9a
    SERIAL = 0xa1
    PRINT = 0xa3
    MODEM = 0xa4
    MEMW = 0xa6 # aka mCH341_PARA_CMD_W0
    MEMR = 0xac # aka mCH341_PARA_CMD_R0
    SPI = 0xa8
    SIO = 0xa9
    I2C = 0xaa
    UIO = 0xab
    I2C_STATUS = 0x52
    I2C_COMMAND = 0x53
    VERSION = 0x5f # at least in serial mode?

class I2CCommands():
    # These are all from ch341dll.h, mostly untested
    """
    After STA, you can insert MS|millis, and US|usecs to insert a delay
    (you can insert multiple)
    MS|0 = 250ms wait,
    US|0 = ~260usecs?
    US|10 is ~10usecs,
    be careful, US|20 = MS|4!  US|40 = ? (switched back to 20khz mode)
    """
    STA = 0x74
    STO = 0x75
    OUT = 0x80
    IN = 0xc0
    MAX = 32 # min (0x3f, 32) ?! (wrong place for this)
    SET = 0x60 # bit 7 apparently SPI bit order, bit 2 spi single vs spi double
    US = 0x40 # vendor code uses a few of these in 20khz mode?
    MS = 0x50
    DLY = 0x0f
    END = 0x00 # Finish commands with this. is this really necessary?

class PinState():
    """
    This is kinda gross, should be a more pythonic way of doing this?
    I've verified this works on a few pins, not sure about all of them, d7..d0 work.

    """
    ERR = 0x100 # read-write
    PEMP = 0x200 # read-write
    INT = 0x400 # read-write
    SLCT = 0x800 # read-write
    WAIT = 0x2000 # read-write
    DATAS = 0x4000 # "write readable only" ?!
    ADDRS = 0x8000 # "write readable only" ?!
    RESET = 0x10000 # "just write"
    WRITE = 0x20000 # "just write"
    SCL = 0x400000 # read-only
    SDA = 0x800000 # read-only
    DXX = 0xff000000
    def __init__(self, bits):
        if (type(bits) != type(int)):
            # assume it's the raw field from reading i2c status
            out = struct.unpack_from(">IH", bytearray(bits))
            bits = out[0]
            # TODO - no clue what the last word is for.
        s = []
        if bits & self.ERR: s += ["ERR"]
        if bits & self.PEMP: s += ["PEMP"]
        if bits & self.INT: s += ["INT"]
        if bits & self.SLCT: s += ["SLCT"]
        if bits & self.WAIT: s += ["WAIT"]
        if bits & self.DATAS: s += ["DATAS"]
        if bits & self.ADDRS: s += ["ADDRS"]
        if bits & self.RESET: s += ["RESET"]
        if bits & self.WRITE: s += ["WRITE"]
        if bits & self.SCL: s += ["SCL"]
        if bits & self.SDA: s += ["SDA"]
        if bits & self.DXX:
            datax = (bits & self.DXX) >> 24
            for i in range(8):
                if (1<<i) & datax:
                    s += ["D%d" % i]
        self.as_bits = bits
        self.names = s

    def __str__(self):
        return "Pins[" + ",".join(self.names) + "]"

class CH341():
    """
    TODO - make this behave more like python-smbus. (be as api compat as possible!)
    """
    EP_OUT = 2
    EP_IN = 0x82

    def vendor_read(self, req, wValue, wIndex, len):
        return self.dev.ctrl_transfer(CtrlCommands.READ_TYPE, req, wValue, wIndex, len)

    def __init__(self, vid=0x1a86, pid=0x5512):
        dev = usb.core.find(idVendor=vid, idProduct=pid)
        if not dev:
            raise ValueError("Device not found (%x:%x" % (vid, pid))
        log.info("Found device (%x:%x) version: %d.%d",
                 vid, pid, dev.bcdDevice >> 8, dev.bcdDevice & 0xff)
        # These devices only have one that I know of...
        assert(dev.bNumConfigurations == 1)
        dev.set_configuration()
        self.dev = dev
        # i2c vs epp vs mem mode? or is this fixed?
        log.debug("Device protocol? %d", dev.bDeviceProtocol)

        #ch34x_vendor_read( VENDOR_VERSION, 0x0000, 0x0000, serial, buf, 0x02 );
        #static int ch34x_vendor_read( __u8 request,__u16 value,  __u16 index,
        #                struct usb_serial *serial, unsigned char *buf, __u16 len )
        #retval = usb_control_msg( serial->dev, usb_rcvctrlpipe(serial->dev, 0),
        #                request, VENDOR_READ_TYPE, value, index, buf, len, 1000 );
        vv = self.vendor_read(VendorCommands.VERSION, 0, 0, 2)
        log.info("vendor version = %d.%d (%x.%x)", vv[0], vv[1], vv[0], vv[1])
        iss = self.vendor_read(VendorCommands.I2C_STATUS, 0, 0, 8)
        log.debug("i2c status = %s, pins = %s", iss, PinState(iss))

    def set_speed(self, speed=100):
        """
        Set the i2c speed desired
        :param speed: in khz, will round down to 20, 100, 400, 750
        :return: na
        20 and 100 work well, 400 is not entirely square, but I don't think it's meant to be
        750 is closer to 1000 for bytes, but slower around acks and each byte start.
        All seem to work well.
        """
        sbit = 1
        if speed < 100:
            sbit = 0
        elif speed < 400:
            sbit = 1
        elif speed < 750:
            sbit = 2
        else:
            sbit = 3

        # TODO ^ how does linux handle this sort of stuff normally?
        # logging when it doesn't match?
        cmd = [VendorCommands.I2C, I2CCommands.SET | sbit, I2CCommands.END]
        count = self.dev.write(self.EP_OUT, cmd)
        assert count == len(cmd), "Failed to write cmd to usb"

    def i2c_start(self):
        """
        Just a start bit...
        :return:
        """
        cmd = [VendorCommands.I2C, I2CCommands.STA, I2CCommands.END]
        log.debug("writing: %s", [hex(cc) for cc in cmd])
        cnt = self.dev.write(self.EP_OUT, cmd)
        assert(cnt == len(cmd))

    def i2c_stop(self):
        # This doesn't seem to be very reliable :(
        cmd = [VendorCommands.I2C, I2CCommands.STO, I2CCommands.END]
        log.debug("writing: %s", [hex(cc) for cc in cmd])
        cnt = self.dev.write(self.EP_OUT, cmd)
        assert(cnt == len(cmd))

    def i2c_detect(self, addr):
        """
        Use the single byte write style to get an ack bit from writing to an address with no commands.
        :param addr:
        :return: true if the address was acked.
        """
        cmd = [VendorCommands.I2C,
               I2CCommands.STA, I2CCommands.OUT, addr, I2CCommands.STO, I2CCommands.END]
        log.debug("writing: %s", [hex(cc) for cc in cmd])
        cnt = self.dev.write(self.EP_OUT, cmd)
        assert(cnt == len(cmd))
        rval = self.dev.read(self.EP_IN, I2CCommands.MAX)
        assert(len(rval) == 1)
        return not (rval[0] & 0x80)

    def i2c_write_byte_check(self, bb):
        """
        write a byte and return the ack bit
        :param bb: byte to write
        :return: true for ack, false for nak
        """
        cmd = [VendorCommands.I2C, I2CCommands.OUT, bb, I2CCommands.END]
        log.debug("writing: %s", [hex(cc) for cc in cmd])
        cnt = self.dev.write(self.EP_OUT, cmd)
        assert(cnt == len(cmd))
        rval = self.dev.read(self.EP_IN, I2CCommands.MAX)
        assert(len(rval) == 1)
        return not (rval[0] & 0x80)
        log.debug("read in %s", rval)

    def i2c_read_block(self, length):
        """
        Requests a read of up to 32 bytes
        :return: array of data
        """
        # not sure why/if this needs a -1 like I seemed to elsewhere
        #cmd = [VendorCommands.I2C, I2CCommands.IN | length, I2CCommands.END]
        cmd = [VendorCommands.I2C, I2CCommands.IN, I2CCommands.END]
        cnt = self.dev.write(self.EP_OUT, cmd)
        assert(cnt == len(cmd))
        rval = self.dev.read(self.EP_IN, I2CCommands.MAX)
        print(len(rval), length)
        log.debug("read in %s", rval)
        return rval

    """
else // i2c write operation
        {
            ob[k++] = CH341_CMD_I2C_STREAM;
            ob[k++] = CH341_CMD_I2C_STM_STA;  // START condition
            ob[k++] = CH341_CMD_I2C_STM_OUT | (msgs[i].len + 1);
            ob[k++] = msgs[i].addr << 1;  // address byte

            memcpy(&ob[k], msgs[i].buf, msgs[i].len);
            k = k + msgs[i].len;

            // if the message is the last one, add STOP condition
            if (i == num-1)
                ob[k++]  = CH341_CMD_I2C_STM_STO;

            ob[k++]  = CH341_CMD_I2C_STM_END;

            // write address byte and data
            result = ch341_usb_transfer (ch341_dev, k, 0);
        }
    """
    def i2c_write(self, slave_addr, reg_addr, data: bytearray):
        cmd = [VendorCommands.I2C, I2CCommands.STA, I2CCommands.OUT | len(data) + 2, slave_addr << 1, reg_addr]
        cmd += data
        cmd += [I2CCommands.STO, I2CCommands.END]
        log.debug("writing: %s", [hex(cc) for cc in cmd])
        cnt = self.dev.write(self.EP_OUT, cmd)
        assert(cnt == len(cmd))
        
    """
    if (msgs[i].flags & I2C_M_RD) // i2c read operation
        {
            ob[k++] = CH341_CMD_I2C_STREAM;
            ob[k++] = CH341_CMD_I2C_STM_STA;       // START condition
            ob[k++] = CH341_CMD_I2C_STM_OUT | 0x1; // write len (only address byte)
            ob[k++] = (msgs[i].addr << 1) | 0x1;   // address byte with read flag

            if (msgs[i].len)
            {
                for (j = 0; j < msgs[i].len-1; j++)
                    ob[k++] = CH341_CMD_I2C_STM_IN | 1;

                ob[k++] = CH341_CMD_I2C_STM_IN;
            }

            // if the message is the last one, add STOP condition
            if (i == num-1)
                ob[k++]  = CH341_CMD_I2C_STM_STO;

            ob[k++] = CH341_CMD_I2C_STM_END;

            // wirte address byte and read data
            result = ch341_usb_transfer(ch341_dev, k, msgs[i].len);

            // if data were read
            if (result > 0)
            {
                if (msgs[i].flags & I2C_M_RECV_LEN)
                {
                    msgs[i].buf[0] = result;  // length byte
                    memcpy(msgs[i].buf+1, ib, msgs[i].len);
                }
                else
                {
                    memcpy(msgs[i].buf, ib, msgs[i].len);
                }
            }
        }
    """
    
    def i2c_read(self, slave_addr, length):
        cmd = [VendorCommands.I2C, I2CCommands.STA, I2CCommands.OUT | 0x01, slave_addr << 1 | 0x01]
        
        if length > 0:
            for i in range(length - 1):
                cmd += [I2CCommands.IN | 0x01]
            cmd += [I2CCommands.IN]
            
        cmd += [I2CCommands.STO, I2CCommands.END]
        log.debug("writing: %s", [hex(cc) for cc in cmd])
        cnt = self.dev.write(self.EP_OUT, cmd)
        assert(cnt == len(cmd))
        rval = self.dev.read(self.EP_IN, I2CCommands.MAX)
        log.debug("read: %s", [hex(cc) for cc in rval])
        return rval
        
        
    def register_read(self, slave_addr, reg_addr, length):
        self.i2c_write(slave_addr, reg_addr, [])
        return self.i2c_read(slave_addr, length)
        
    def register_write(self, slave_addr, reg_addr, data: bytearray):
        self.i2c_write(slave_addr, reg_addr, data)
        
    
def scan(q):
    results = []
    for i in range(250):
        r = q.i2c_detect(i)
        print("address: %d (%#x) is: %s" % (i, i, r))
        if r: results += [i]
    print("Responses from i2c devices at: ", results, [hex(a) for a in results])


if __name__ == "__main__":
    q = CH341()
    q.set_speed(400)
    scan(q)

