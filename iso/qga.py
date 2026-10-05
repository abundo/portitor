#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Runs a command in an iso/vm.sh guest through the QEMU guest agent:

    iso/qga.py SOCKET CMD...

prints its output and exits with its status (255: no guest agent).
"""

import base64
import json
import socket
import sys
import time

path, cmd = sys.argv[1], sys.argv[2:]
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(path)
    f = s.makefile("rw")

    def call(execute, **args):
        f.write(json.dumps({"execute": execute, "arguments": args}) + "\n")
        f.flush()
        while True:
            reply = json.loads(f.readline())
            if "return" in reply or "error" in reply:
                if "error" in reply:
                    raise RuntimeError(reply["error"])
                return reply["return"]

    # Drop replies left on the socket by an earlier, timed out client.
    call("guest-sync", id=4711)
    pid = call("guest-exec", path=cmd[0], arg=cmd[1:], **{"capture-output": True})["pid"]
    while not (st := call("guest-exec-status", pid=pid))["exited"]:
        time.sleep(0.5)
except Exception:
    sys.exit(255)
for k, out in (("out-data", sys.stdout), ("err-data", sys.stderr)):
    if k in st:
        out.write(base64.b64decode(st[k]).decode(errors="replace"))
sys.exit(st.get("exitcode", 1))
