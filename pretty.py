#!/usr/bin/env python3

import sys
import json
from dataclasses import dataclass

if len(sys.argv) != 2:
    print("ERROR: Please pass path to file")
    exit(1)

f_path = sys.argv[1]
if f_path == "-":
    j = json.load(sys.stdin)
else:
    with open(f_path, "r") as f:
        j = json.load(f)

insn_bytes = j["input"]

@dataclass
class Results:
    status: bool
    result: str

def worker_name(s: str) -> str:
    return s.split('./src/worker/', 1)[1].split('/', 1)[0]

def success(s: str) -> bool:
    return s == "success"

collection = dict()
for o in j["outputs"]:
    collection[worker_name(o["worker_so"])] = Results(success(o["status"]["name"]), o["result"])

print(f"Instruction bytes: '{insn_bytes}'")
for worker, result in collection.items():
    print(f"{worker: <12}: {result.result: <30} {result.status}")
