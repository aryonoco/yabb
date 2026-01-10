# YABB

Yet Another BTRFS Backup. Incremental snapshots with retention policies.

[![REUSE](https://api.reuse.software/badge/github.com/aryonoco/yabb)](https://api.reuse.software/info/github.com/aryonoco/yabb)
![License](https://img.shields.io/badge/license-MPL--2.0-blue)
![Nim](https://img.shields.io/badge/nim-2.2%2B-yellow)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

**Alpha software.** Works for my use case, but expect breaking changes before 1.0.

## What it does

YABB creates BTRFS snapshots, sends them to a backup location, and optionally deletes old ones.

- Full and incremental backups (only sends changes)
- Retention policies (keep 6 hourly, 7 daily, etc.)
- Delete any snapshot without breaking the chain, even intermediate ones
- Snapshots carry their own metadata (no external tracking files)
- Chain length limits (forces full backup after N incrementals)
- Chain recovery when things go wrong
- Dry-run mode to see what would happen
- JSON output for scripting
- Runs as a single static binary

## Why another backup tool?

There are already good BTRFS backup and snapshot tools out there:

- [btrbk](https://github.com/digint/btrbk) - Flexible, supports remote backups via SSH
- [Snapper](https://github.com/openSUSE/snapper) - Mature, popular on openSUSE, great rollback support
- [Timeshift](https://github.com/linuxmint/timeshift) - User-friendly GUI, excellent for system rollbacks
- [btrfs-backup](https://github.com/efficiosoft/btrfs-backup) - Simple incremental backups with send/receive
- [Btrfs-Assistant](https://gitlab.com/btrfs-assistant/btrfs-assistant) - GUI for Snapper

I tried these but none worked exactly how I wanted for my specific setup. So I wrote
YABB to scratch my own itch and also to teach myself Nim. Publishing it in case someone else finds it useful; not
because the tools above aren't good.

## Requirements

- Linux with BTRFS filesystems (source and destination)
- Root access
- `btrfs-progs` 5.14+ (for `--compressed-data`)
- Standard tools: `pv`, `flock`, `setfattr`, `getfattr`
- Nim 2.2+ (Only if you want to build it from source yourself)

## Install

### Automatic (recommended)

```bash
curl -fsSL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/aryonoco/yabb/main/scripts/setup-yabb.sh | sudo bash
# Edit /etc/yabb.toml
sudo systemctl enable yabb.service
sudo systemctl enable yabb.timer
sudo systemctl start yabb.timer
```

The installer automatically installs config, shell completions, and systemd files to their locations. It never overwrites existing config files.

To update: `sudo /opt/yabb/scripts/setup-yabb.sh`

To uninstall: `sudo /opt/yabb/scripts/setup-yabb.sh --remove`

### Build from source

```bash
git clone https://github.com/aryonoco/yabb.git
cd yabb
just build-static
sudo cp bin/yabb /usr/local/bin/
sudo cp config/yabb.toml.example /etc/yabb.toml
# Edit /etc/yabb.toml
```

For a dynamically linked release build: `just build-release`

## Configuration

Sample `/etc/yabb.toml`:

```toml
[paths]
src_dir = "/data"           # What to back up
dst_dir = "/backup"         # Where snapshots go
snapshot_dir = "/snapshots" # Local snapshot storage

[compression]
algorithm = "zstd"
level = 10

[retention]
hourly = 24
daily = 7
weekly = 4
monthly = 6
yearly = 2

[chain]
max_length = 10  # Force full snapshot after this many incrementals

[options]
min_free_space = 1024  # MB
```

All three paths must be on BTRFS.

## Usage

```bash
# Run a backup
yabb run

# See what would happen without doing it
yabb run --dryRun

# Force a full snapshot instead of incremental
yabb run --forceFull

# Check your config is valid
yabb validate

# See current snapshots
yabb status

# Check chain health, fix if broken
yabb health --repair

# Manual storage maintenance
yabb optimize
```

### Automation

YABB includes service files.
The installer automatically installs these to `/etc/systemd/system/`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable yabb.service
sudo systemctl enable yabb.timer
# Enable daily backups
sudo systemctl start yabb.timer
```

Check status: `systemctl list-timers yabb*`

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | No changes (not an error) |
| 2 | Bad arguments |
| 3 | Config file missing |
| 4-5 | Config errors |
| 6 | Missing prerequisite |
| 7 | Invalid directory |
| 8 | Lock held (another instance running) |
| 9 | Lock error |
| 10 | BTRFS device errors |
| 11 | Killed by signal |

## Shell completions

The installer installs shell completions to the following locations:
- Bash: `/etc/bash_completion.d/yabb`
- Zsh: `/usr/local/share/zsh/site-functions/_yabb`
- Fish: `/usr/share/fish/vendor_completions.d/yabb.fish`

Restart your shell to enable completions.

If building from source, install manually:
```bash
sudo cp completions/yabb.bash /etc/bash_completion.d/yabb
sudo cp completions/yabb.zsh /usr/local/share/zsh/site-functions/_yabb
sudo cp completions/yabb.fish /usr/share/fish/vendor_completions.d/
```

## How it works

<details>
<summary>Architecture</summary>

Written in Nim. Functional core, imperative shell pattern.

```
src/
├── cli.nim         # Command dispatch
├── config.nim      # TOML parsing
├── btrfs/          # Snapshot operations
├── chain/          # Chain management & recovery
├── retention/      # What to keep, what to delete
└── utils/          # Locking, paths, retries
```

Backup flow: load config → acquire lock → create snapshot → apply retention → release lock.

No exceptions. Everything returns `Result[T, Error]`.

</details>

## Contributing

1. Fork it
2. Make changes
3. Run `just ci`
4. Submit a PR

Code style: `func` for pure functions, `proc` only for side effects. Versioning follows [SemVer](https://semver.org/).

## AI/LLM Disclosure

This project was developed with significant LLM involvement. I'm a systems architect by trade, not a programmer. I designed the core logic, made technical decisions and directed development, but AI/LLM tools generated most of the code.

All code was reviewed, tested, and iterated on by me. The design choices (Result types over exceptions, functional patterns, safety configuration, etc) are mine. The Nim syntax is not.
I'm publishing this because it works for me, not because of how it was written.

## License

Copyright 2023-2026 Aryan Ameri.

| Content | License |
|---------|---------|
| Source code | [MPL-2.0](LICENSES/MPL-2.0.txt) |
| Config/plumbing | [0BSD](LICENSES/0BSD.txt) |
| Documentation | [CC-BY-4.0](LICENSES/CC-BY-4.0.txt) |

This project is [REUSE](https://reuse.software/) compliant. See [REUSE.toml](REUSE.toml) for details.
