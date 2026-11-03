# Bloody terminal art

The letter glyphs and cyan ANSI palette in bloody.json were exported from
[TAAG](https://patorjk.com/software/taag/), using **Bloody Cyan / TheDraw**.
They are bundled as data so the console works offline without extra packages.

The original font has no numeric glyphs. The 4 used in **WibeH4Ck** and
**Log4Shell** is a local addition in the same style. No other digits are
silently substituted: unsupported text uses a readable plain title.

Each glyph has ten padded rows. A row contains its text and a matching shade
string: c = cyan, h = white on cyan, w = white, d = gray,
b = cyan on cyan. Letter shapes and highlights come from the TAAG export.
