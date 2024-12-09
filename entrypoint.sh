#!/bin/bash

crond -f -d 8 &
python3 ecs_sg_manager.py
tail -f /dev/null
