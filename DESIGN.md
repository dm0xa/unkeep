---
name: unkeep
description: A light, typographic surface for a secret that can be read only once.
colors:
  ink: "#0b0c0e"
  ink-2: "#3d4249"
  muted: "#5b6169"
  line: "#e4e6e9"
  line-2: "#8c9299"
  well: "#f7f8f9"
  paper: "#ffffff"
  accent: "#c2700c"
  accent-strong: "#a85e08"
  accent-ink: "#0b0c0e"
  danger: "#d0382a"
  danger-well: "#fcf1ef"
  dark-paper: "#0b0c0e"
  dark-ink: "#f3f4f6"
  dark-ink-2: "#c2c7ce"
  dark-muted: "#9aa1aa"
  dark-line: "#23262a"
  dark-line-2: "#686e75"
  dark-accent: "#f2b45e"
  dark-danger: "#e2604f"
typography:
  display:
    fontFamily: "Archivo, ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "clamp(2.5rem, 5vw, 4rem)"
    fontWeight: 580
    lineHeight: 1.02
    letterSpacing: "-0.035em"
  lede:
    fontFamily: "Archivo, ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "normal"
  body:
    fontFamily: "Archivo, ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "normal"
  label:
    fontFamily: "Archivo, ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "normal"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.7
    letterSpacing: "normal"
rounded:
  control: "10px"
  switch: "6px"
  dialog: "14px"
  dot: "50%"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "24px"
  xl: "36px"
  section: "48px"
  gutter: "40px"
  split: "16px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.control}"
    padding: "0 22px"
    height: "52px"
    typography: "{typography.label}"
  button:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 22px"
    height: "52px"
    typography: "{typography.label}"
  choice-option:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    padding: "12px 8px"
    height: "46px"
    typography: "{typography.label}"
  choice-option-selected:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
    rounded: "{rounded.control}"
  input:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 18px"
    height: "52px"
    typography: "{typography.body}"
  textarea:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "18px"
    typography: "{typography.mono}"
---

# Design System: unkeep

## Overview

**Creative North Star: "The plain sheet"**

A single ink on white paper, set by someone who trusts the reader. Nothing is
drawn that could be said: no panels, no uppercase labels, no borders around
groups. The page is a column of type at editorial scale; one amber accent marks
action and state, and red appears only where something is destroyed.

The system is asymmetric by intent. The action occupies roughly two thirds of a
1180 px grid; the remaining third carries the mechanism as a three-step flow —
Write it, Lock it, Send the link — separated by hairlines. The flow is the
product's argument, and it sits in space rather than in a box. On the create
page the form is compact enough that the amber primary action lands in the
first viewport.

**Key Characteristics:**

- White ground, one near-black ink, one amber accent, one red, hairline greys.
- Archivo, self-hosted, at a 4 rem display against 1 rem body.
- No shadows, no elevation, no card borders; separation is space and hairlines.
- Controls are the only filled surfaces, and only when selected or primary.
- The open u is the brand's one flourish; amber carries focus and state.

## Colors

A two-tone page with one amber accent and one red held back for destruction.
The dark scheme is the same system with the two tones exchanged — ink becomes
the ground, the ground becomes ink. It follows `prefers-color-scheme` until the
reader pins a theme with the corner control; the choice is stored per browser.

### Primary
- **Ink** (`#0b0c0e`): All text and the selected expiry chip.
- **Accent** (`#c2700c` light / `#f2b45e` dark): The amber that carries action
  and state — primary button fill, the switch's on-track, focus rings, the
  favicon's u, the copied dot, the live/gone dots, the callout dot, the flow
  dots. Never body text: 3.7:1 on white.
- **Accent ink** (`#0b0c0e`): The label on amber in both schemes. 5:1 light,
  11:1 dark.

### Neutral
- **Paper** (`#ffffff`): The page. No tinted ground anywhere.
- **Ink 2** (`#3d4249`): Ledes, secondary prose, callout copy.
- **Muted** (`#5b6169`): Labels, timestamps, helper text, placeholder text.
  6.2:1 on paper.
- **Line** (`#e4e6e9`): Row dividers and the footer rule.
- **Line 2** (`#8c9299`): Control borders at rest, 3.1:1 on paper.
- **Well** (`#f7f8f9`): The security callout's ground; the only near-surface
  tint, used once per page.

### Tertiary
- **Danger** (`#d0382a` light / `#e2604f` dark): Destruction only — the burned
  state, the revoke action, field errors. It never decorates.

### Dark scheme
- **Ground** `#0b0c0e`, **ink** `#f3f4f6`, **ink 2** `#c2c7ce`, **muted**
  `#9aa1aa`, **hairlines** `#23262a`, **control borders** `#686e75`.
- The primary button stays amber, lifted to `#f2b45e` with a near-black label;
  the red rises to `#e2604f`.
- Control boundaries hold at 3:1 or better in both schemes (WCAG 1.4.11).
- Both schemes come from the same `light-dark()` token pairs, so a pinned
  theme only flips `color-scheme`; no second palette exists.

### Named Rules
**The Inversion Rule.** Dark is the same system with ink and paper exchanged,
never a second palette. There is no colour that appears in only one scheme.

### Named Rules
**The One Accent Rule.** Amber fills the primary action, the switch's on-track,
the favicon, and the 6 px state dots; it draws focus rings and field focus. It
never becomes a heading, a decorative border, or body text. There is no second
accent hue.

### Named Rules
**The One Red Rule.** Red marks a record that is gone or an action that destroys
one. Using it for warnings, emphasis, or brand voice is a defect.

## Typography

**Display Font:** Archivo, variable, self-hosted (`font-weight: 100 900`)
**Body Font:** Archivo, same file
**Mono Font:** system monospace stack

**Character:** A grotesk with a tall x-height and flat terminals, set very
tight at display size and left completely plain at reading size. The contrast
between 64 px and 16 px is the hierarchy; nothing else needs to carry rank.

### Hierarchy
- **Display** (580, `clamp(2.5rem, 5vw, 4rem)`, 1.02, `-0.035em`): Page
  titles only, one or two lines, max 16–18ch.
- **Lede** (400, 1.125rem, 1.55): One sentence under the title, max 64ch;
  the create page's lede holds one line at desktop.
- **Body** (400, 1rem, 1.55): Notes and explanations, max 48ch.
- **Label** (500, 0.9375rem): Field labels and buttons. Sentence case, never
  uppercase, never tracked.
- **Mono** (400, 0.9375rem, 1.7): The secret, links, timestamps, counters.

### Named Rules
**The No Eyebrow Rule.** No small uppercase label ever sits above a heading.
Headings stand on their own.

## Layout

A 1180 px content grid with 40 px gutters, split `1fr / 19rem` with a 64 px
gap. The left column carries the task; the right column carries the mechanism —
a three-step flow on the create page, and a 22 px statement plus one paragraph
on the reveal pages. Below 992 px the split collapses to a single column with
the aside following the task, and below 640 px the gutters drop to 20 px and
the display to 2.35rem.

The create page is tuned so the primary action sits inside a 768 px viewport:
16 px above the split, 20 px between the head and the form, 14 px between form
groups. The field head row carries the label, the counter, and the storage note
on one baseline; the expiry legend carries its own explanation. Rows are
separated by 1 px hairlines, never by spacing alone when the row is a list.

## Elevation & Depth

There is none. The system is flat: no shadows, no blur, no elevation steps.
Depth would imply layering, and nothing here is layered — every element is on
the same sheet. Focus is the only state that draws a ring, and it is 2 px of
amber offset 2–3 px. Fields replace the ring with an amber border and a 3 px
amber halo.

## Shapes

Controls are rounded rectangles at 10 px; the passphrase switch track at 6 px;
the help dialog at 14 px; dots at 6 px. Everything else is a rectangle of type
with no box. Borders are always 1 px and always `--line-2` at rest, amber when
focused, ink when selected. Nothing is pill-shaped. The only circles are the
state dots and the help step numbers; the only chip shape is the expiry
option.

## Components

### Buttons
- **Shape:** 10 px radius, 52 px tall.
- **Primary:** amber fill, near-black label, 22 px side padding, full width in
  forms. On the create form: "Create one-time link"; on the result, "Copy link".
- **Secondary:** white with a 1 px `line-2` border, ink label.
- **Quiet:** underlined text, no border, for tertiary paths.
- **Danger:** red underlined text; never a filled red button.
- **Hover / Focus:** the primary darkens to `--accent-strong`; active
  translates 1 px down; disabled drops to 35% opacity.

### Inputs / Fields
- **Style:** white fill, 1 px `line-2`, 10 px radius, 52 px tall. The secret
  field is a five-row mono textarea (165 px) that grows with its content to
  384 px, then scrolls.
- **Head row:** label left; the byte counter, a mid dot, and "What we hold is
  already encrypted" right on one baseline, 0.6 rem below. The note hides below
  640 px, leaving label and counter on one line.
- **Focus:** border turns amber with a 3 px amber halo.
- **Error:** border and text go to `--danger`, fill to `--danger-well`.
- **Placeholder:** `--muted` (6.2:1), never lighter.

### Expiry choice
- Four equal columns, one row at desktop and two rows below 640 px. Unselected
  are white with a `line-2` border; the selected one is ink-filled with paper
  text. The radio itself is invisible and covers the option, so the whole chip
  is the target. The legend reads "Delete if unread after", which carries the
  explanation without a second hint line.

### Passphrase switch
- A 44 × 24 px track with a 6 px radius and a 14 px knob, not a pill.
- One row, "Add a passphrase" left and switch right, is one `<label>`: the
  whole row toggles.
- Off is a paper track with a `line-2` border; on is amber with an ink knob.
- Turning it on reveals a mono input with inline **Copy** and **Generate**
  controls and focuses it. Generate writes a ten-word grammatical phrase
  (about 39 bits), switches the field to text, and focuses it; Copy copies it.
  The hint below reads "At least 8 characters. Share it another way. Without
  it, the link is useless." Turning it off clears the field.
- The inline controls are 32 px tall, 6 px radius, `--well` ground, 12 px 600;
  Copy confirms with an amber border and label.

### Security callout
- One per create page, directly above the primary action. Well ground, 10 px
  radius, 0.55 rem vertical padding, an amber 6 px dot, and 14 px `ink-2` copy
  with the claim in ink: whoever opens the link first gets the secret, so it
  should not be sent somewhere that saves history. It swaps copy once a
  passphrase is on and holds two lines at desktop.

### Mechanism flow
- The create page's aside is three rows: Write it, Lock it, Send the link.
  Each row is an amber 6 px dot plus 15 px `ink-2` text, with 1 px hairlines
  above and between. "Once it's opened, it's deleted. Nothing is kept." sits
  below at 15 px. No numbers, no arrows, no card.

### Rows
- **Facts row:** label in `--muted` and value in ink, inline pairs separated by
  2.5 rem, wrapping at 40 rem. Used on the reveal for Expires, Time left,
  Confirm within, and Reads left.
- **Meta row:** label left in `--muted`, value right in ink, 1 px divider,
  0.8 rem vertical padding. In the aside, label and value stack.
- **Log row:** event label and mono timestamp on one line, detail beneath,
  hairline between rows.
- **Reveal steps:** three numbered rows; the number is 14 px mono in `--muted`,
  the text 15 px `--ink-2`, 1 px hairlines between.

### Theme toggle
- A 34 px icon button in the masthead corner, beside the help control: a moon
  while the page is light, a sun while it is dark. It states what pressing it
  will do, not the current mode.
- A click pins the theme in `localStorage`; with no stored value the page
  follows the OS and the glyph tracks it.

### Help
- A 34 px "?" button sits before the theme toggle, with the same 1 px border
  and 8 px radius. It carries "How unkeep works" as its accessible name and
  opens a native `<dialog>`.
- The dialog is at most 32 rem wide and 80 dvh tall, 14 px radius, 1 px
  `line`, 1.5 rem padding, on a 32% ink backdrop. It holds a 1.35 rem 600
  title, a Close text button, one lede, three numbered steps in 20 px circles,
  and a 12 px muted note. Esc, Close, and a backdrop click dismiss it; focus
  rings are amber.
- The help and reveal steps are true sequences, so they carry numbers; no
  section heading does.

### Footer
- Two quiet items on one hairline: "No accounts, no database, no plaintext."
  and a 16 px GitHub mark linking to the source. The icon is `--muted`,
  becomes ink on hover, and carries "Source code on GitHub" as its accessible
  name. The repo link is a placeholder pointing at github.com until the
  repository is public.

### Amber marks
- **Wordmark:** a 22 px open u — the bowl cut away at the bottom centre —
  followed by nkeep in Archivo 600 at 20 px, -0.03em. The u is drawn at a
  2.35 stroke so the larger initial reads at the same weight as the wordmark.
  Ink in the masthead; the favicon sets the same open u in `--accent` on an
  ink square.
- **Copied:** the share and secret copy buttons invert to ink, add a 6 px amber
  dot after the label, and reset after 1.8 s. The inline passphrase Copy stays
  small and confirms with an amber border and label instead.
- **Gone:** the reveal status reads "Read and gone." and prepends a 6 px amber
  dot that appears and fades once over 900 ms.
- **Focus, live, flow, callout:** the same 6 px dot or 2 px ring in the same
  amber; no other colour is used for state.

### State chip
- A 6 px dot plus 14 px text. Amber when live, `--danger` when the record is
  closed, `line-2` while connecting.

## Do's and Don'ts

### Do:
- **Do** let type size and space carry hierarchy; the next step down is
  usually space, not weight.
- **Do** keep prose at 44–64ch and the display at 16–18ch.
- **Do** use red only where something is destroyed, and keep destructive
  actions as underlined text so they cannot be hit by accident.
- **Do** keep the mechanism as a three-row flow with amber dots, not a card or
  a second headline.
- **Do** keep the primary action inside the first viewport at 768 px; compact
  the form before shrinking the display.
- **Do** match the open u's 2.35 stroke to the 600 wordmark; the larger initial
  must not read bolder.

### Don't:
- **Don't** add shadows, elevation, or card borders; the sheet is flat.
- **Don't** put a caption or icon above a heading, or an uppercase label
  anywhere.
- **Don't** use amber for body text, headings, or decorative borders; focus
  rings and field focus are the exception.
- **Don't** use a filled red button, a red heading, or red emphasis.
- **Don't** introduce a third typeface or a second accent hue.
- **Don't** centre the page or wrap the form in a card.
