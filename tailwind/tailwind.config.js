/** @type {import('tailwindcss').Config} */
module.exports = {
  // Class strategy: dark mode is toggled by adding `dark` to <html>.
  darkMode: "class",

  // Scan every Django template so utility classes used directly in markup
  // are emitted. New webapps that use raw utility classes must be added here
  // (and the CSS rebuilt). Webapps that stick to the reusable component
  // classes in input.css work without a rebuild.
  content: [
    "../armory2/armory_main/templates/**/*.html",
    "../armory2/armory_main/included/webapps/**/templates/**/*.html",
  ],

  theme: {
    extend: {
      colors: {
        // Brand accent for the modernized UI.
        brand: {
          50: "#eef6ff",
          100: "#d9eaff",
          200: "#bcdaff",
          300: "#8ec3ff",
          400: "#59a1ff",
          500: "#327dff",
          600: "#1b5ff5",
          700: "#1449e1",
          800: "#173cb6",
          900: "#19388f",
        },
      },
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
    },
  },

  // Semantic badge color variants are applied via `class` strings built in
  // templates (e.g. `badge badge-success`), so make sure they survive purge.
  safelist: [
    "badge-primary",
    "badge-info",
    "badge-dark",
    "badge-secondary",
    "badge-success",
    "badge-warning",
    "badge-danger",
  ],

  plugins: [],
};
