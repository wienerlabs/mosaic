"use client";

import { useState, useEffect } from "react";

type Item = { num: string; label: string; target: string };

const items: Item[] = [
  { num: "01", label: "Splash", target: "magazine" },
  { num: "02", label: "Release state", target: "page-02" },
  { num: "03", label: "Verifier matrix", target: "page-03" },
  { num: "04", label: "Decision matrix", target: "page-04" },
  { num: "05", label: "Soundness gates", target: "page-05" },
  { num: "06", label: "Compute budgets", target: "page-06" },
  // Session 117 — runtime evidence section inserted between
  // CU budgets and quick start. Subsequent indices shifted +1.
  { num: "07", label: "Runtime evidence", target: "page-07" },
  { num: "08", label: "Quick start", target: "page-08" },
  { num: "09", label: "Architecture", target: "page-09" },
  { num: "10", label: "Release lineage", target: "page-10" },
  { num: "11", label: "Documentation", target: "page-11" },
  { num: "12", label: "Constraints", target: "page-12" },
  { num: "13", label: "Built by Wiener Labs", target: "page-13" },
];

export function NavMenu() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  const go = (target: string) => {
    const el =
      target === "magazine"
        ? document.querySelector<HTMLElement>("main.magazine")
        : document.getElementById(target);
    setOpen(false);
    setTimeout(() => {
      el?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 300);
  };

  return (
    <>
      <button
        className="menu-icon"
        type="button"
        aria-label={open ? "Close menu" : "Open menu"}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span />
        <span />
      </button>

      <div
        className={`nav-overlay ${open ? "is-open" : ""}`}
        onClick={() => setOpen(false)}
        aria-hidden={!open}
      >
        <aside
          className={`nav-panel ${open ? "is-open" : ""}`}
          onClick={(e) => e.stopPropagation()}
          role="dialog"
          aria-label="Main navigation"
        >
          <div className="nav-head">
            <span className="tag">INDEX // NAVIGATION</span>
            <button
              className="nav-close"
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Close menu"
            >
              CLOSE ✕
            </button>
          </div>
          <nav>
            <ul className="nav-list">
              {items.map((item, i) => (
                <li key={item.num} style={{ "--i": i } as React.CSSProperties}>
                  <button
                    className="nav-link"
                    type="button"
                    onClick={() => go(item.target)}
                  >
                    <span className="nav-num">{item.num}</span>
                    <span className="nav-label">{item.label}</span>
                    <span className="nav-arrow">→</span>
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          <div className="nav-foot">
            <a
              href="https://github.com/wienerlabs/mosaic"
              target="_blank"
              rel="noopener"
            >
              github.com/wienerlabs/mosaic
            </a>
            <a href="https://x.com/mosaiczk" target="_blank" rel="noopener">
              x.com/mosaiczk
            </a>
          </div>
        </aside>
      </div>
    </>
  );
}
