# uhara10-PBZ

A small fork of [ru-mii/uhara](https://github.com/ru-mii/uhara) for work on the
Phantom Blade Zero LiveSplit autosplitter. It is not a rewrite or a replacement
for upstream.

uhara10 is by ru-mii. The upstream README says they have stopped working on the
project and are prioritizing other things, and that the repository remains open
for forks. Thank you for making uhara available; best wishes to them.

## Changes

The Phantom Blade Zero changes are limited to:

- `TMemory`: a module image cache keyed by process token and module name, used
  by the scan helpers instead of re-reading the module for each scan.
- `ReadMemoryBytes`: a chunked-read fallback for large reads.
- `Default.Utilities.DataRetriever`: a Phantom Blade Zero GEngine signature,
  tried before the existing candidates.

No public API or identifier changes.

## Reference

[UE4SS for Phantom Blade Zero](https://www.nexusmods.com/phantombladezero/mods/5)
by Vercadi on Nexus Mods was used as reference material while identifying
Phantom Blade Zero addresses and signatures for this fork. UE4SS itself is by
[UE4SS-RE and its contributors](https://github.com/UE4SS-RE/RE-UE4SS).

## Status

Focused on Phantom Blade Zero. The changes have not been verified against a
live game; initialization timings and compatibility with other games are not
established.

## Upstream

Source, compiled versions and helper tools for the original project are
maintained at [ru-mii/uhara](https://github.com/ru-mii/uhara). Upstream builds
are not builds of this fork.
