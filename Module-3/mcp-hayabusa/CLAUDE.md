# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

This repository is currently empty — no code has been written yet. The sections below describe the intended purpose and design so that implementation can start from a shared understanding.

## Purpose

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (a Windows event log / EVTX analysis and threat-hunting tool) so that MCP clients can run EVTX scans and receive structured results.

## Goals

- Expose a `scan_evtx` MCP tool that runs the Hayabusa CLI against EVTX files.
- Return results as structured JSON (not raw Hayabusa CLI output).
- Support filtering scan results by severity level.
- Handle errors gracefully (e.g. missing/invalid EVTX files, Hayabusa CLI failures, malformed output) and surface them as clear MCP tool errors rather than crashing the server.

## Stack

- Python, using the `mcp` library to implement the MCP server.
- Hayabusa CLI, installed locally and invoked as a subprocess.

## Architecture Notes (for implementation)

- The `scan_evtx` tool should shell out to the local Hayabusa binary, parse its output (e.g. JSON/JSONL output mode if supported), and normalize it into the tool's structured JSON response.
- Severity filtering should be applied consistently whether Hayabusa supports it natively via CLI flags or whether it needs to be filtered post-hoc from Hayabusa's output.
- Since this wraps an external CLI binary, treat the Hayabusa executable path/version as an environment-specific dependency — do not hardcode a path if it can be discovered or configured.
