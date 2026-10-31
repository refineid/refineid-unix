# The command line

How `refineid` is shaped, and why. The rules are in `AGENTS.md` under
"Command line"; this file is the reasoning behind them, with the
literature each rule leans on and what that literature does not settle.
Citations are BibTeX keys in [`references.md`](references.md).

## The shape

- **Noun first, then verb.** `refineid document sign FILE`, `refineid
  pin change`, `refineid cert chain`. The first word names the thing
  acted on; the second names the action. Where a group has a natural
  readout, the bare noun is it: `refineid card` reads the card.
- **Two listings, one vocabulary.** Bare `refineid` lists the everyday
  commands: the card, its PINs, signing a document, the paired phone.
  `refineid expert` lists the rest: raw keys and data, offline
  certificate tools, the reader. The word `expert` is a view, never
  typed before a command; every command has one name.
- **Help in three depths.** The listing names commands in one line
  each and fits a screen; `refineid <command> help` shows a command's
  options; the man page refineid(1) carries the detail, split into the
  same two sections. No command prints a banner or its version
  unasked; `-V` does that.
- **Quiet on success.** An operation prints nothing when it works and
  reports its steps with `-v`. The exit status tells success from
  failure, so `&&` and `||` compose.
- **Secrets at the terminal only.** A PIN is asked once the card is in
  hand, read from the terminal, never from the command line, and
  nothing is echoed while it is typed.
- **Names a shell can pass back.** A signed document is
  `<stem>-signed-<UTC time>.<ext>`: the user's stem untouched, and a
  suffix that adds no spaces.
- **Prefixes for typing, full words for scripts.** A command word may
  be shortened to any prefix that names one command, so `refineid doc
  s` signs a document; a prefix that fits several is refused with the
  candidates, never guessed.
- **Completion that cannot drift.** `packaging/zsh/_refineid` is
  generated from the command table at development time and checked in,
  so every package installs a plain file and nothing runs at package
  time; a test fails while the file is stale, and another holds each
  command's completable options to the options its help text names.

## Why

**Families share a head word; pairs are named as pairs.** Carroll's
command-language experiments found two properties of a command set that
made it easier to learn and recall: congruence, where opposed commands
are named as a pair (`pair` / `unpair`, not `pair` / `forget`), and
hierarchicalness, where a family shares a head word and differs in a
modifier (`pin activate`, `pin change`, `pin unblock`)
([carroll1982paradigms](references.md#carroll1982paradigms)). Noun-first
naming is what makes the hierarchy fall out of the grammar, and it gives
`refineid pin help` something to mean.

**The set's regularity matters more than any one word.** Black and
Moran found no memory advantage for names users chose themselves over
names a designer chose; what helped was names that are specific and
discriminable from one another
([black1982commandnames](references.md#black1982commandnames)). Landauer,
Galotti and Hartwell found that names chosen to be natural gave no
advantage in initial learning, while giving differently behaving
operations different names did
([landauer1983naturalnames](references.md#landauer1983naturalnames)).
Hence no two commands differ only in a word that means the same thing,
and arguments about `sign` versus `sign-document` are settled by the
family's regularity, not taste.

**Show the few, hold the many.** Norman's 1981 critique of the UNIX
command set is that it puts everything in front of everyone with
nothing to tell the frequent from the rare
([norman1981unix](references.md#norman1981unix)); Nielsen's heuristic
of recognition over recall says a short list the user can scan beats a
long one they must remember
([nielsen1994heuristics](references.md#nielsen1994heuristics)). The two
listings are that: a screenful for the card holder, and the engineering
tools one word away.

**Truncation is the abbreviation people reach for.** Streeter, Ackroff
and Taylor compared abbreviation schemes and found truncation the best
single scheme for producing an abbreviation from a command name, and
the one people use unprompted for longer words
([streeter1983abbreviating](references.md#streeter1983abbreviating)).
They also name the two problems of a unique prefix, that it is harder
to learn than a fixed cut and that a new command can make an old prefix
ambiguous, and their answers are ours: an ambiguous prefix is an error
that names the candidates, never a guess, scripts spell commands out,
and a prefix need only be unique within its noun group, so `doc s` is
`document sign` even if some other group gains an `s` word.

**People will not guess our words; we do not add theirs.** Furnas and
colleagues measured how often two people choose the same word for the
same thing and found it rarely above one in five
([furnas1987vocabulary](references.md#furnas1987vocabulary)). Their
remedy was many synonyms. We take the finding and refuse the remedy:
one name per command, and the listing plus completion to bridge the
guess. This is a choice against one strand of the evidence, recorded as
such in [Evidence we do not
have](references.md#evidence-we-do-not-have).

**Consistency is a means.** Grudin shows that consistency pursued for
its own sake can make an interface worse when it forces unlike things
into like shapes
([grudin1989consistency](references.md#grudin1989consistency)). So `card`
and `phone` are parallel where the parallel is real, a readout and the
actions on the thing, and not forced further.

**Silence is the UNIX rule.** A program that has nothing surprising to
say says nothing; the convention is recorded as the Rule of Silence
([raymond2003unix](references.md#raymond2003unix)). It is convention,
not measurement, and we follow it because the shell's composition
depends on it.

**No echo for a PIN.** This is not a research question. An echoed
mask puts the PIN's length on the screen, in the scrollback and in any
recording of the terminal; login(1) and sudo(8) echo nothing, and so
does `refineid`.
