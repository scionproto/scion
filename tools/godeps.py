#!/usr/bin/python3

# Stdlib
import json
import subprocess


def main():
    top = subprocess.check_output(["go", "list", "-e"],
                                  universal_newlines=True).strip()
    raw = subprocess.check_output(["go", "list", "-json", "./go/..."],
                                  universal_newlines=True)

    def impFilter(dep):
        return not dep.startswith(top) and "/" in dep

    decoder = json.JSONDecoder()
    deps = set()
    while raw:
        data, index = decoder.raw_decode(raw)
        raw = raw[index+1:]  # Skip trailing newline
        deps.update(filter(impFilter, data.get("Imports", [])))
        deps.update(filter(impFilter, data.get("TestImports", [])))
    for dep in sorted(deps):
        print("%s/..." % dep)

if __name__ == "__main__":
    main()
