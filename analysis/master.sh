#!/bin/bash

echo "DOING R1"

cd r1
bash parse.sh

cd ..
echo "DOING R4"
cd r4
bash parse.sh

