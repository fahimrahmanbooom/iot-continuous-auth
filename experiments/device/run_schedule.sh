#!/usr/bin/env bash
# Physical event schedule used on 9 October 2026. Reboots at 15:17:52 (manual),
# 15:24:59 and 15:27:30 UTC had already run; this schedule ran the rest.
set -u
cd "$(dirname "$0")/../.."
PY=.venv/bin/python
EV=experiments/device/physical_events.py
gap=75
sleep 150   # let the restarted server accept the messages that will be replayed
$PY $EV replay --age 120;          sleep $gap
$PY $EV replay --age 120 --forge;  sleep $gap
$PY $EV reboot;                    sleep $gap
$PY $EV replay --age 120;          sleep $gap
$PY $EV replay --age 120 --forge;  sleep $gap
$PY $EV reboot;                    sleep $gap
$PY $EV replay --age 120;          sleep $gap
echo "schedule complete"
