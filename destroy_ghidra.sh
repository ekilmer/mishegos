#!/usr/bin/env bash

./src/mish2jsonl/mish2jsonl /tmp/mishegos > /tmp/mishegos.jsonl
./src/analysis/analysis -p destroy-ghidra < /tmp/mishegos.jsonl > /tmp/mishegos.interesting

split -d --lines=10000 - /tmp/mishegos_destroy_ghidra_ --additional-suffix='.html' --filter='./src/mishmat/mishmat > $FILE' < /tmp/mishegos.interesting
