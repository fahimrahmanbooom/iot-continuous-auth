#!/usr/bin/env bash
# Remaining final-phase events after the 16:08:40 server restart.
set -u
cd "$(dirname "$0")/../.."
PY=.venv/bin/python
EV=experiments/device/physical_events.py
gap=75
sleep 150   # let the restarted server accept the messages that will be replayed
$PY $EV reboot;                    sleep $gap
$PY $EV replay --age 120 --forge;  sleep $gap
$PY $EV reboot;                    sleep $gap
$PY $EV replay --age 120;          sleep $gap
$PY $EV reboot;                    sleep $gap
echo "schedule complete"
