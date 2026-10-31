#!/usr/bin/env zsh
# Shows what the zsh completion offers for each command line given:
#   script/test/zsh-completion.zsh packaging/zsh 'refineid doc s --'
# Drives an interactive zsh in a pseudo-terminal, loads _refineid from
# the directory named, presses Tab after each line and prints the
# listing. For eyes, not for a gate: the output is a terminal's.
zmodload zsh/zpty
dir=$1; shift
drain() {  # read until the pty is quiet for ~0.4 s; result in $REPLY
  local chunk acc="" quiet=0
  while (( quiet < 4 )); do
    if zpty -r -t z chunk 2>/dev/null; then acc+=$chunk; quiet=0; else sleep 0.1; (( quiet++ )); fi
  done
  REPLY=$acc
}
zpty -b z zsh -f -i
zpty -w z "PS1='> '; fpath=($dir \$fpath); autoload -Uz compinit; compinit -u -D; zstyle ':completion:*' list-rows-first false; zstyle ':completion:*' menu no; zstyle ':completion:*' format ''; zstyle ':completion:*:descriptions' format ''; setopt nolistbeep nobeep; unsetopt listambiguous; bindkey '^I' complete-word; bindkey '^U' kill-whole-line"
sleep 1; drain
for line in "$@"; do
  zpty -w -n z "$line"$'\t'
  sleep 0.3; drain
  out=${REPLY//$'\e'\[[0-9;?]#[a-zA-Z]/}; out=${out//$'\r'/}
  print -r -- "=== $line<TAB>"
  print -r -- "$out" | grep -v '^\s*$' | head -14
  zpty -w -n z $'\x15'; sleep 0.2; drain
done
zpty -d z
