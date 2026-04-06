/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        vektor: {
          bg: "#0A0F1C",
          "bg-light": "#111827",
          "bg-card": "#151D2E",
          accent: "#3B82F6",
          "accent-hover": "#2563EB",
          green: "#10B981",
          "green-dim": "#065F46",
          red: "#EF4444",
          amber: "#F59E0B",
          border: "#1E293B",
          "text-primary": "#F8FAFC",
          "text-secondary": "#94A3B8",
          "text-muted": "#64748B",
        },
      },
      fontFamily: {
        sans: ["DM Sans", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      animation: {
        "fade-in": "fadeIn 0.6s ease-out",
        "slide-up": "slideUp 0.6s ease-out",
        "pulse-slow": "pulse 3s ease-in-out infinite",
        "glow": "glow 2s ease-in-out infinite alternate",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(20px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        glow: {
          "0%": { boxShadow: "0 0 5px rgba(59,130,246,0.3)" },
          "100%": { boxShadow: "0 0 20px rgba(59,130,246,0.6)" },
        },
      },
    },
  },
  plugins: [],
};
