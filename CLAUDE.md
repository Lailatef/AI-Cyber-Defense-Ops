# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A Python tool that parses Sysmon XML event logs and extracts key fields from
**Event ID 1 (Process Creation)** events, emitting them as JSON.

Fields to extract from each Event ID 1 record:
- `EventID`
- `UtcTime`
- `Image` (process path)
- `CommandLine`
- `User`
- `IntegrityLevel`
- `ParentImage`
- `ParentCommandLine`
- `Computer`
- `Hashes`

Output: JSON — one object per event, or a JSON array when parsing multiple events.

## Project status

No source code has been written yet. This file will be updated with real
build/lint/test commands and architecture notes once the implementation exists.

When implementing, resolve and document:
- Input source: raw Sysmon XML (`.evtx`-exported XML, or XML fragments) and how it's read
- The XML→field extraction approach (e.g. `xml.etree.ElementTree`, `lxml`) given
  Sysmon's XML uses a default namespace on `<Event>`/`<EventData>`/`<Data>` elements
- CLI interface (input path(s)/stdin, output path/stdout, single vs. array output)
- How non-Event-ID-1 events are handled (skipped vs. error)
- Test strategy, including sample Sysmon XML fixtures for Event ID 1
