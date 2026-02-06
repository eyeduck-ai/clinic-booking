if (typeof tailwind !== "undefined") {
  tailwind.config = {
    darkMode: "class",
    theme: {
      extend: {
        colors: {
          primary: "#2E6F6A",
          "primary-hover": "#255B56",
          "primary-dark": "#1D4744",
          surface: "#ffffff",
          "surface-2": "#f5f1ea",
          ink: "#1b2421",
          muted: "#6f7f79",
          "background-light": "#f7f3ed",
          "background-dark": "#111815",
        },
        fontFamily: {
          display: ["Noto Serif TC", "serif"],
          body: ["IBM Plex Sans", "Noto Sans TC", "sans-serif"],
        },
        borderRadius: {
          DEFAULT: "0.25rem",
          lg: "0.5rem",
          xl: "0.75rem",
          "2xl": "1rem",
          full: "9999px",
        },
        boxShadow: {
          card: "0 10px 30px rgba(15, 23, 42, 0.08)",
        },
      },
    },
  };
}
