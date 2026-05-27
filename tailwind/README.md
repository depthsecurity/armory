# Armory web UI styling (Tailwind)

The Armory web UI is styled with [Tailwind CSS](https://tailwindcss.com/) (v3).
This directory holds the **build source**; the compiled, minified stylesheet is
committed into the package at:

```
../armory2/armory_main/static/armory_main/css/tailwind.css
```

so end users never need Node to run Armory. `htmx` is likewise vendored at
`../armory2/armory_main/static/armory_main/js/htmx.min.js`.

## Files

| File                 | Purpose                                                        |
|----------------------|----------------------------------------------------------------|
| `input.css`          | Source: `@tailwind` directives + reusable component classes.   |
| `tailwind.config.js` | Theme tokens, dark-mode strategy, template content paths.      |
| `package.json`       | `build` / `watch` scripts.                                     |

## Rebuilding the CSS

Run after editing `input.css`, `tailwind.config.js`, or after adding **new raw
utility classes** in any Django template (component classes in `input.css` are
always emitted and don't require a rebuild):

```bash
cd tailwind
npm install      # first time only
npm run build    # one-off minified build
npm run watch    # rebuild on change during development
```

Commit the regenerated `tailwind.css`.

## Theming & reuse

- **Dark mode**: toggled by adding `dark` to `<html>`. The base template
  (`armory_main/base_tw.html`) sets the initial theme before first paint from
  `localStorage` (`armory-theme`) falling back to OS preference, and persists
  the user's choice.
- **Reusable classes** (defined in `input.css`, usable from any webapp without a
  rebuild): `armory-container`, `armory-card` / `armory-card-body` /
  `armory-card-title` / `armory-card-text`, `armory-section-title`,
  `badge` + `badge-{primary,info,dark,secondary,success,warning,danger}`,
  `btn` + `btn-{primary,secondary,ghost}`, `armory-input`, `nav-link` /
  `nav-link-active`.

New webapps should `{% extends 'armory_main/base_tw.html' %}` to inherit the
nav, theme toggle, and styling. Existing webapps still on Bootstrap continue to
extend `armory_main/base.html`.
