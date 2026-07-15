# Shell tab-completion for `armory`

`armory` supports tab completion via [argcomplete](https://github.com/kislyuk/argcomplete)
(already a dependency). Completion works for:

- **Base flags** — `armory -<TAB>` / `armory --<TAB>` (`-m`, `-r`, `-lm`, `-lr`, `--docker`, …)
- **Module names** — `armory -m <TAB>` lists every available module (built-in + custom)
- **Report names** — `armory -r <TAB>` lists every available report
- **Per-tool options** — once a module/report is chosen, its own flags complete too,
  e.g. `armory -m Nmap --<TAB>` offers `--hosts`, `--rescan`, `--filter_ports`, …

## Setup

Source the script for your shell from your shell rc file.

### zsh (`~/.zshrc`)

```zsh
# Requires compinit (Oh-My-Zsh and most setups already call it):
autoload -U compinit && compinit
source /path/to/armory/contrib/armory-completion.zsh
```

### bash (`~/.bashrc`)

```bash
source /path/to/armory/contrib/armory-completion.bash
```

Open a new shell (or `source ~/.zshrc`) and press `<TAB>`.

## Alternative: register directly

The scripts here are the static output of argcomplete's registration helper.
If you'd rather generate them yourself (e.g. after upgrading argcomplete), run
the helper from armory's environment. With a pipx install:

```bash
eval "$(~/.local/pipx/venvs/depth-armory/bin/register-python-argcomplete armory)"
```

(`register-python-argcomplete` lives inside armory's virtualenv, not on `$PATH`,
which is why the ready-to-source scripts are provided here.)

## Notes

- Each `<TAB>` briefly starts the `armory` process; completing a tool's own
  options loads that one module/report to read its arguments. The database is
  never touched during completion.
- Module/report **name** matching is case-sensitive during completion (type
  `Nmap`, not `nmap`); running the tool itself remains case-insensitive.
