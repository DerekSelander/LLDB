# Copilot Instructions

## Project snapshot
- This repo is a grab bag of LLDB extensions; every script in `lldb_commands/` becomes an LLDB command once `dslldb.py` is imported from `~/.lldbinit`.
- The loader treats `.py` files as `command script import` targets and `.txt` files as `command source` scripts, so adding files in that folder immediately changes what LLDB loads.
- `ds.py` is the shared utility hub for colorized output, SBExpression configuration, section parsing, and shell helpers; most commands import it.

## Essential workflows
- Installation: clone, point `~/.lldbinit` at `lldb_commands/dslldb.py`, then call the `reload_lldbinit` alias defined in `cmds.txt` after editing any script.
- Development happens inside a paused LLDB session; helpers like `ds.isProcStopped()` guard commands that expect the process to be halted.
- There are no automated tests—sanity check changes by attaching LLDB to a sample process, running `(lldb) help <command>` to confirm registration, and exercising the command manually.

## Script anatomy & conventions
- Each command file exports `__lldb_init_module(debugger, internal_dict)` and registers handlers via `debugger.HandleCommand('command script add ...')`; see `lookup.py` or `search.py` for the standard structure.
- Use the utilities in `ds.py` instead of rolling custom LLDB boilerplate: `genExpressionOptions` sets the ObjC/Swift evaluation defaults, `attrStr` wraps ANSI color unless running under Xcode, and `sys` executes shell commands with a rooted PATH.
- Prefer structured parsing (`argparse`/`optparse`) and expose usage via `-h`; the built-in generator in `generate_new_script.py` scaffolds both function-style and class-style commands in the expected layout.
- When producing textual output, follow existing patterns: cap noisy results (`search.py` limits to 100 hits) and color important fields with `ds.attrStr`.

## Supporting assets
- `cmds.txt` seeds a library of `command alias`/`command regex` helpers (filesystem access, CoreAnimation flush, Objective-C ivar dumps). Adding new aliases here will auto-load on the next `reload_lldbinit`.
- `settings.txt` contains LLDB presentation defaults (Intel syntax, disassembly count, etc.) that get applied on import—keep formatting consistent and avoid commands that require user interaction.
- The `Media/` directory only feeds README documentation; don’t reference it from runtime code.

## External boundaries & gotchas
- Commands assume ObjC/Swift symbols and Foundation availability; gate features that require Apple-private selectors with friendly error messages when they’re missing.
- Avoid third-party Python packages—LLDB ships a limited Python, so everything must stick to the standard library or helpers under `compat/`.
- Be mindful of side effects: scripts like `search` and `yoink` can leak memory or touch the filesystem; document any new ones in the README if they affect device state.
