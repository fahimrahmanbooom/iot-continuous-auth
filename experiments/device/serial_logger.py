"""Log ESP32 serial output with host UTC timestamps."""
import sys
import time
from datetime import datetime, timezone

import serial

port, path = sys.argv[1], sys.argv[2]
while True:
    try:
        dev = serial.Serial()
        dev.port, dev.baudrate, dev.timeout = port, 115200, 1
        dev.dtr = False  # do not touch reset/boot lines when attaching
        dev.rts = False
        dev.open()
        with dev, open(path, "a", encoding="utf-8") as out:
            while True:
                line = dev.readline()
                if line:
                    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                    out.write(f"{stamp} {line.decode(errors='replace').rstrip()}\n")
                    out.flush()
    except (serial.SerialException, OSError):
        time.sleep(1)  # port disappears briefly while the board resets
