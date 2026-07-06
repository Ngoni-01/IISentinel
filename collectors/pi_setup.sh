#!/bin/bash
# IISentinel Pi Edge Node — one-shot setup for fresh Raspberry Pi OS
set -e
echo "IISentinel Pi setup starting..."
sudo apt-get update -qq
sudo apt-get install -y python3-pip i2c-tools
sudo raspi-config nonint do_i2c 0 || true
pip3 install --break-system-packages requests adafruit-circuitpython-dht mpu6050-raspberrypi RPi.GPIO || \
pip3 install requests adafruit-circuitpython-dht mpu6050-raspberrypi RPi.GPIO
echo ""
echo "Setup done. Next steps:"
echo "  1. Register:  python3 pi_collector.py --server https://YOUR-APP.onrender.com --register \"$(hostname)\""
echo "  2. Put the printed API key into pi_collector.service (Environment=IIS_COLLECTOR_KEY=...)"
echo "  3. sudo cp pi_collector.service /etc/systemd/system/"
echo "  4. sudo systemctl enable --now pi_collector"
