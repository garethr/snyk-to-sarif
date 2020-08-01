#!/usr/bin/env python

"""
This script turns the standard Snyk JSON output from the CLI into
a SARIF file compatible with GitHub Security.

It's been implemented purely using the Python standard library and
with a fair amount of brute force. Caveat emptor.
"""

# TODO: Error handling
# TODO: Cache Dockerfile line lookups
# TODO: Formatting
# TODO: Support adding additional tags

import argparse
import json
import sys


def find_line_number(path, data, key):
    try:
        lookup = data[key]
        with open(path) as handle:
            for num, line in enumerate(handle, 1):
                if lookup in line:
                    return num
        return None
    except (FileNotFoundError, KeyError):
        return None


parser = argparse.ArgumentParser(description="Convert Snyk JSON output to SARIF")
parser.add_argument("input", type=str, help="Path to the Snyk JSON file")
parser.add_argument(
    "--file",
    metavar="path",
    type=str,
    default="Dockerfile",
    help="Path to file under test (default: Dockerfile)",
)
parser.add_argument(
    "--output",
    "-o",
    metavar="path",
    type=str,
    help="Path to save the SARIF file, defaults to stdout",
)

args = parser.parse_args()

if args.input == "-":
    data = "".join([x.strip() for x in sys.stdin.readlines()])
    snyk = json.loads(data)
else:
    with open(args.input) as handle:
        snyk = json.load(handle)

manifest_file_path = args.file

rules = {}
results = []

for vuln in snyk["vulnerabilities"]:
    level = "error" if vuln["severity"] == "high" else "warning"

    title = vuln["title"]
    name = vuln["name"]
    package_name = vuln["packageName"]
    version = vuln["version"]
    severity = vuln["severity"]

    try:
        cwes = vuln["identifiers"]["CWE"]
    except KeyError:
        cwes = []

    tags = cwes
    # The security tag is used by GitHub to identify security issues
    tags.append("security")

    try:
        cve = vuln["identifiers"]["CVE"][0]
    except KeyError:
        cve = None

    short_description = (
        f"{severity.capitalize()} severity {title} vulnerability in {package_name}"
    )
    full_description = f"({cve}) {name}@{version}" if cve else f"{name}@{version}"
    message = f"This file introduces a vulnerable {package_name} package with a {severity} severity vulnerability."

    rules[vuln["id"]] = {
        "id": vuln["id"],
        # This appears as the title on the list and individual issue view
        "shortDescription": {"text": short_description},
        # This appears as a sub heading on the individual issue view
        "fullDescription": {"text": full_description},
        # This appears on the individual issue view in an expandable box
        "help": {
            "markdown": vuln["description"],
            # This property is not used if markdown is provided, but is required
            "text": "",
        },
        "defaultConfiguration": {"level": level},
        "properties": {"tags": tags},
    }

    instruction_line = find_line_number(manifest_file_path, vuln, "dockerfileInstruction")
    from_line = find_line_number(manifest_file_path, vuln, "dockerBaseImage")

    line = instruction_line or from_line or 1

    result = {
        "ruleId": vuln["id"],
        # This appears in the line by line highlight on the individual issue view
        "message": {"text": message,},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": manifest_file_path},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    results.append(result)


sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Snyk", "rules": list(rules.values())}},
            "results": results,
        }
    ],
}

if args.output:
    with open(args.output, "w") as handle:
        json.dump(sarif, handle)
else:
    print(json.dumps(sarif))
