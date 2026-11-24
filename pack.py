#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a byte-for-byte reproducible JAR from out/wxaudit/*.class.

Why not `jar cfm`: the jar CLI stamps META-INF entries with wall-clock time,
so two identical builds produce different SHA256 hashes. A JAR is a ZIP with
a META-INF/MANIFEST.MF, so writing the ZIP directly with fixed timestamps
gives deterministic output that Java loads identically.
"""
import os
import sys
import zipfile

FIXED_TIME = (2020, 1, 1, 0, 0, 0)
MANIFEST = "Manifest-Version: 1.0\nCreated-By: wxaudit build\n\n"


def entry(zf, name, data, is_dir=False):
    info = zipfile.ZipInfo(name, FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o40755 if is_dir else 0o100644) << 16
    zf.writestr(info, b"" if is_dir else data)


def main():
    classes = []
    base = os.path.join("out", "wxaudit")
    for root, _dirs, files in os.walk(base):
        for name in sorted(files):
            if name.endswith(".class"):
                full = os.path.join(root, name)
                arc = "wxaudit/" + os.path.relpath(full, base).replace(os.sep, "/")
                classes.append((arc, open(full, "rb").read()))
    if not classes:
        print("ERROR: no compiled classes found in out/wxaudit", file=sys.stderr)
        sys.exit(1)

    with zipfile.ZipFile("wxaudit-burp.jar", "w") as zf:
        entry(zf, "META-INF/", None, is_dir=True)
        entry(zf, "META-INF/MANIFEST.MF", MANIFEST.encode("utf-8"))
        entry(zf, "wxaudit/", None, is_dir=True)
        for arc, data in sorted(classes):
            entry(zf, arc, data)
    print("packed %d classes -> wxaudit-burp.jar" % len(classes))


if __name__ == "__main__":
    main()
