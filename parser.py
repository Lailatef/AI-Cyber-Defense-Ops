#!/usr/bin/env python3
"""Parse Sysmon Event ID 1 (Process Creation) XML into JSON."""

import argparse
import json
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

DATA_FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]


def parse_event(event_elem):
    system = event_elem.find("e:System", NS)
    event_id = system.findtext("e:EventID", namespaces=NS)
    if event_id != "1":
        return None

    record = {"EventID": int(event_id)}

    event_data = event_elem.find("e:EventData", NS)
    data_by_name = {
        data.get("Name"): (data.text or "")
        for data in event_data.findall("e:Data", NS)
    }
    for field in DATA_FIELDS:
        record[field] = data_by_name.get(field)

    record["Computer"] = system.findtext("e:Computer", namespaces=NS)

    return record


def parse_file(path):
    tree = ET.parse(path)
    root = tree.getroot()

    if root.tag == f"{{{NS['e']}}}Event":
        event_elems = [root]
    else:
        event_elems = root.findall("e:Event", NS)

    records = [r for r in (parse_event(e) for e in event_elems) if r is not None]
    return records


def matches_filters(record, args):
    if args.image and args.image.lower() not in (record["Image"] or "").lower():
        return False
    if args.user and args.user.lower() != (record["User"] or "").lower():
        return False
    if args.integrity_level and args.integrity_level != record["IntegrityLevel"]:
        return False
    if args.command_line and args.command_line.lower() not in (record["CommandLine"] or "").lower():
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Parse Sysmon Event ID 1 (Process Creation) XML into JSON.")
    parser.add_argument("path", help="Path to Sysmon XML log file")
    parser.add_argument("--image", help="Filter by Image (substring match, case-insensitive)")
    parser.add_argument("--user", help="Filter by User (exact match, case-insensitive)")
    parser.add_argument(
        "--integrity-level",
        choices=["High", "Medium", "Low", "System"],
        help="Filter by IntegrityLevel (exact match)",
    )
    parser.add_argument("--command-line", help="Filter by CommandLine (substring match, case-insensitive)")
    args = parser.parse_args()

    records = parse_file(args.path)
    records = [r for r in records if matches_filters(r, args)]

    if len(records) == 1:
        print(json.dumps(records[0], indent=2))
    else:
        print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
