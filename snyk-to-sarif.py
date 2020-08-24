#!/usr/bin/env python

"""
This script turns the standard Snyk JSON output from the CLI into
a SARIF file compatible with GitHub Security.

It's been implemented purely using the Python standard library and
with a fair amount of brute force. Caveat emptor.
"""

import argparse
import json
import sys


def cache_line_number(func):
    """
    The standard libary lru_cache requires hashable arguments
    so this decorator is hard coded to build a custom cache key
    out of specific arguments
    """
    cache = dict()

    def memoized_find_line_number(path, data, key):
        # We cache only on a subset of arguments as although the data
        # will change most of it is not pertinent to the return value
        cache_key = f"{path}/{key}"
        if cache_key in cache:
            return cache[cache_key]
        result = func(path, data, key)
        cache[cache_key] = result
        return result

    return memoized_find_line_number


@cache_line_number
def find_line_number(path, data, key):
    """
    Return the line number of a particular string from
    a specified file or None if not found. Responses are cached
    in the context of a single execution
    """
    try:
        lookup = data[key]
        with open(path) as handle:
            for num, line in enumerate(handle, 1):
                if lookup in line:
                    return num
        return None
    except (FileNotFoundError, KeyError):
        return None


class SnykToSarif:
    """
    Snyk can produce a JSON file containing vulnerability information
    SARIF is an OASIS standard for describing issues of all types in source code,
    most commonly applieed to forms of static analysis
    This class helps convert from Snyk JSON to SARIF, for integration with
    other tooling, including GitHub Security
    """

    def __init__(self, tags=[]):
        self.tags = tags

    def from_file(self, path):
        """
        You can manually set self.snyk to a string, but this method
        helps with setting that based on a file path, including supporting
        `-` as a reference to stdin.
        """
        if path == "-":
            data = "".join([x.strip() for x in sys.stdin.readlines()])
            self.snyk = json.loads(data)
        else:
            with open(path) as handle:
                self.snyk = json.load(handle)

    def convert(self, file_path):
        """
        Method to convert to SARIF. Maps the various fields from Snyk to the
        equivalent or similar in SARIF. This is optimised for GitHub Security
        which has specific SARIF opinions. The resulting file may work with
        other SARIF implementations.
        """
        rules = {}
        results = []

        # Most Snyk JSON files will have known vulnerabilities
        # but (for example) Infrastructure as Code projects won't
        if "vulnerabilities" in self.snyk and self.snyk["vulnerabilities"]:
            target_file = file_path or self.snyk["displayTargetFile"]

            for vuln in self.snyk["vulnerabilities"]:
                # SARIF only has error and warning levels for detected issues
                # We set high severity issues as errors and everything else as warning
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

                tags = cwes + self.tags
                # The security tag is used by GitHub to identify security issues
                tags.append("security")

                try:
                    cve = vuln["identifiers"]["CVE"][0]
                except KeyError:
                    cve = None

                short_description = f"{severity.capitalize()} severity {title} vulnerability in {package_name}"
                full_description = (
                    f"({cve}) {name}@{version}" if cve else f"{name}@{version}"
                )
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

                instruction_line = find_line_number(
                    target_file, vuln, "dockerfileInstruction"
                )
                from_line = find_line_number(target_file, vuln, "dockerBaseImage")

                line = instruction_line or from_line or 1

                result = {
                    "ruleId": vuln["id"],
                    # This appears in the line by line highlight on the individual issue view
                    "message": {"text": message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target_file},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                }
                results.append(result)

        if "infrastructureAsCodeIssues" in self.snyk:
            target_file = file_path or self.snyk["targetFile"]

            for issue in self.snyk["infrastructureAsCodeIssues"]:
                if not issue["isIgnored"]:

                    level = "error" if issue["severity"] == "high" else "warning"

                    title = issue["title"]
                    severity = issue["severity"]
                    type_name = (
                        "kubernetes" if issue["type"] == "k8s" else issue["type"]
                    )
                    sub_type = issue["subType"]
                    short_description = f"{severity.capitalize()} severity {title}"
                    full_description = f"{type_name.capitalize()} {sub_type}"

                    message = f"This line contains a potential {severity} severity misconfiguration affacting the {type_name.capitalize()} {sub_type}"

                    tags = self.tags
                    # The security tag is used by GitHub to identify security issues
                    tags = ["security"]
                    tags.append(f"{type_name}/{sub_type}".lower())

                    rules[issue["id"]] = {
                        "id": issue["id"],
                        # This appears as the title on the list and individual issue view
                        "shortDescription": {"text": short_description},
                        # This appears as a sub heading on the individual issue view
                        "fullDescription": {"text": full_description},
                        # This appears on the individual issue view in an expandable box
                        "help": {
                            "markdown": issue["description"],
                            # This property is not used if markdown is provided, but is required
                            "text": "",
                        },
                        "defaultConfiguration": {"level": level},
                        "properties": {"tags": tags},
                    }

                    result = {
                        "ruleId": issue["id"],
                        # This appears in the line by line highlight on the individual issue view
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": target_file},
                                    "region": {"startLine": issue["lineNumber"]},
                                }
                            }
                        ],
                    }
                    results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Snyk", "rules": list(rules.values())}},
                    "results": results,
                }
            ],
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Snyk JSON output to SARIF")
    parser.add_argument("input", type=str, help="Path to the Snyk JSON file")
    parser.add_argument(
        "--file",
        metavar="path",
        type=str,
        help="Path to file under test if different from Snyk JSON output",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="path",
        type=str,
        help="Path to save the SARIF file, defaults to stdout",
    )
    parser.add_argument(
        "--tag",
        "-t",
        action="append",
        help="Add additional tags all results",
        default=[],
    )

    args = parser.parse_args()

    snyk_to_sarif = SnykToSarif(args.tag)

    try:
        snyk_to_sarif.from_file(args.input)
    except json.JSONDecodeError as e:
        print(f"Problem decoding JSON from {args.input}")
        sys.exit(1)
    except IOError as e:
        print(f"Problem opening file ({type(e).__name__}) {args.input}")
        sys.exit(1)

    sarif = snyk_to_sarif.convert(args.file)

    try:
        if args.output:
            with open(args.output, "w") as handle:
                json.dump(sarif, handle)
        else:
            print(json.dumps(sarif))
    except TypeError as e:
        print(f"Problem saving JSON: {e}")
        sys.exit(1)
    except IOError as e:
        print(f"Problem opening file ({type(e).__name__}) {args.output}")
        sys.exit(1)
