"use client";

import { useEffect, useState } from "react";

const STORAGE_KEY = "mosaic-theme";

type Theme = "light" | "dark";

function getInitialTheme(): Theme {
  if (typeof window === "undefined") return "light";
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === "dark" || stored === "light") return stored;
  return "light";
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("light");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const initial = getInitialTheme();
    setTheme(initial);
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme, mounted]);

  const handleClick = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    window.localStorage.setItem(STORAGE_KEY, next);
    setTheme(next);
  };

  return (
    <button
      className="theme-toggle"
      type="button"
      aria-label="Toggle theme"
      onClick={handleClick}
    >
      {mounted ? (theme === "dark" ? "LIGHT" : "DARK") : "DARK"}
    </button>
  );
}
