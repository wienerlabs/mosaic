"use client";

import { useEffect, useRef } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

gsap.registerPlugin(ScrollTrigger);

// Walks text nodes in element and wraps each word in <span class="word">.
// Preserves <br/> and other elements in the tree.
function splitWords(el: Element) {
  if (el.getAttribute("data-split-done") === "1") return;
  el.setAttribute("data-split-done", "1");

  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  const textNodes: Text[] = [];
  let node: Node | null;
  while ((node = walker.nextNode())) textNodes.push(node as Text);

  textNodes.forEach((tn) => {
    const text = tn.textContent ?? "";
    if (!text.trim()) return;
    const parts = text.split(/(\s+)/);
    const frag = document.createDocumentFragment();
    parts.forEach((part) => {
      if (!part) return;
      if (/^\s+$/.test(part)) {
        frag.appendChild(document.createTextNode(part));
      } else {
        const span = document.createElement("span");
        span.className = "word";
        span.textContent = part;
        frag.appendChild(span);
      }
    });
    tn.parentNode?.replaceChild(frag, tn);
  });
}

function parseStat(raw: string) {
  const trimmed = raw.trim();
  const match = trimmed.match(/^([\d.,]+)(.*)$/);
  if (!match) return null;
  const numStr = match[1];
  const suffix = match[2];
  const value = parseFloat(numStr.replace(/,/g, ""));
  if (Number.isNaN(value)) return null;
  const hasDecimal = numStr.includes(".");
  const hasThousandSep = numStr.includes(",");
  return { value, suffix, hasDecimal, hasThousandSep };
}

function fmt(
  n: number,
  hasDecimal: boolean,
  hasThousandSep: boolean,
  suffix: string
) {
  let str: string;
  if (hasDecimal) {
    str = n.toFixed(1);
  } else if (hasThousandSep) {
    str = Math.round(n).toLocaleString("en-US");
  } else {
    str = Math.round(n).toString();
  }
  return str + suffix;
}

export function GsapAnimations() {
  const initedRef = useRef(false);

  useEffect(() => {
    if (initedRef.current) return;
    initedRef.current = true;

    const killable: Array<{ kill: () => void }> = [];

    // Scroll progress bar.
    const progress = gsap.to(".scroll-progress", {
      scaleX: 1,
      ease: "none",
      scrollTrigger: {
        start: 0,
        end: "max",
        scrub: 0.15,
      },
    });
    if (progress.scrollTrigger) killable.push(progress.scrollTrigger);

    // Splash MOSAIC char reveal (chars pre-split in JSX).
    const chars = gsap.utils.toArray<HTMLElement>(".block-tl .display .char");
    if (chars.length) {
      gsap.from(chars, {
        y: 90,
        rotate: 6,
        opacity: 0,
        duration: 0.9,
        stagger: 0.06,
        ease: "power4.out",
        delay: 0.25,
      });
    }

    // Split sub-display into words then animate.
    const splashSub = document.querySelector(".block-bl .sub-display");
    if (splashSub) {
      splitWords(splashSub);
      const words = splashSub.querySelectorAll(".word");
      if (words.length) {
        gsap.from(words, {
          y: 50,
          opacity: 0,
          duration: 0.8,
          stagger: 0.08,
          ease: "power3.out",
          delay: 0.7,
        });
      }
    }

    // Splash mosaic image + ledes.
    gsap.from(".anim-mosaic", {
      scale: 0.9,
      opacity: 0,
      duration: 1.1,
      delay: 0.35,
      ease: "power3.out",
    });
    gsap.from(".block-tl .tag", {
      x: -30,
      opacity: 0,
      duration: 0.6,
      delay: 0.05,
      ease: "power3.out",
    });
    gsap.from(".block-tl .body-copy", {
      y: 30,
      opacity: 0,
      duration: 0.7,
      delay: 0.55,
      ease: "power3.out",
    });
    gsap.from(".block-bl .tag", {
      y: 30,
      opacity: 0,
      duration: 0.6,
      delay: 0.6,
      ease: "power3.out",
    });
    gsap.from(".block-bl .body-copy", {
      y: 30,
      opacity: 0,
      duration: 0.7,
      delay: 1.1,
      ease: "power3.out",
    });
    gsap.from(".block-br > *", {
      y: 30,
      opacity: 0,
      duration: 0.7,
      stagger: 0.1,
      delay: 0.85,
      ease: "power3.out",
    });
    gsap.from(
      [".magazine .page-num", ".magazine .side-strip .rotated"],
      {
        opacity: 0,
        y: 20,
        duration: 0.6,
        stagger: 0.08,
        delay: 1.3,
        ease: "power2.out",
      }
    );

    // Parallax mosaic.
    const parallax = gsap.to(".anim-mosaic", {
      yPercent: 8,
      ease: "none",
      scrollTrigger: {
        trigger: ".magazine",
        start: "top top",
        end: "bottom top",
        scrub: 0.5,
      },
    });
    if (parallax.scrollTrigger) killable.push(parallax.scrollTrigger);

    // Per-page scroll timelines.
    const pages = gsap.utils.toArray<HTMLElement>(".page");
    pages.forEach((page) => {
      const tag = page.querySelector(".tag");
      const title = page.querySelector(".sub-display");
      if (title) splitWords(title);
      const titleWords = title?.querySelectorAll(".word");
      const lead = page.querySelector(".mag-lead");
      const pageNum = page.querySelector(".page-num");
      const rotated = page.querySelector(".side-strip .rotated");
      const rows = page.querySelectorAll(
        ".mag-table tbody tr, .mag-kv dt, .mag-kv dd, .stat"
      );
      const blocks = page.querySelectorAll(
        ".mag-code-block, .mag-ascii, .mag-footer, .mag-links li"
      );

      const tl = gsap.timeline({
        scrollTrigger: {
          trigger: page,
          start: "top 80%",
          toggleActions: "play none none reverse",
        },
        defaults: { ease: "power3.out" },
      });
      if (tl.scrollTrigger) killable.push(tl.scrollTrigger);

      if (tag) tl.from(tag, { opacity: 0, x: -30, duration: 0.55 });
      if (titleWords && titleWords.length) {
        tl.from(
          titleWords,
          {
            opacity: 0,
            y: 50,
            rotate: 3,
            duration: 0.75,
            stagger: 0.08,
          },
          "-=0.3"
        );
      } else if (title) {
        tl.from(title, { opacity: 0, y: 50, duration: 0.75 }, "-=0.3");
      }
      if (lead)
        tl.from(lead, { opacity: 0, y: 20, duration: 0.55 }, "-=0.4");
      if (rows.length)
        tl.from(
          rows,
          { opacity: 0, y: 24, duration: 0.5, stagger: 0.05 },
          "-=0.3"
        );
      if (blocks.length)
        tl.from(
          blocks,
          { opacity: 0, y: 30, duration: 0.55, stagger: 0.08 },
          "-=0.4"
        );
      if (pageNum)
        tl.from(
          pageNum,
          { opacity: 0, scale: 0.5, duration: 0.55, ease: "back.out(2)" },
          "-=0.3"
        );
      if (rotated)
        tl.from(rotated, { opacity: 0, y: 30, duration: 0.5 }, "-=0.4");
    });

    // Stat counter: animate 0 → target when .stat scrolls into view.
    const stats = document.querySelectorAll<HTMLElement>(".stat-val");
    stats.forEach((el) => {
      const parsed = parseStat(el.textContent ?? "");
      if (!parsed) return;
      const { value, suffix, hasDecimal, hasThousandSep } = parsed;
      const state = { n: 0 };
      el.textContent = fmt(0, hasDecimal, hasThousandSep, suffix);
      const anim = gsap.to(state, {
        n: value,
        duration: 1.8,
        ease: "power2.out",
        scrollTrigger: {
          trigger: el,
          start: "top 85%",
          once: true,
        },
        onUpdate: () => {
          el.textContent = fmt(state.n, hasDecimal, hasThousandSep, suffix);
        },
      });
      if (anim.scrollTrigger) killable.push(anim.scrollTrigger);
    });

    // Checkerboard caption scale-in.
    const interlude = document.querySelector(".checkerboard-interlude");
    const caption = document.querySelector(".checkerboard-caption");
    if (interlude && caption) {
      splitWords(caption.querySelector(".sub-display")!);
      const captionAnim = gsap.from(caption, {
        scrollTrigger: {
          trigger: interlude,
          start: "top 70%",
          toggleActions: "play none none reverse",
        },
        opacity: 0,
        scale: 0.9,
        duration: 0.8,
        ease: "power3.out",
      });
      if (captionAnim.scrollTrigger) killable.push(captionAnim.scrollTrigger);
    }

    // Checkerboard bg pattern drift.
    const checkerboardBg = document.querySelector(".checkerboard-bg");
    let bgAnim: gsap.core.Tween | null = null;
    if (checkerboardBg) {
      bgAnim = gsap.to(checkerboardBg, {
        backgroundPosition: "180px 0px, 315px 135px",
        duration: 14,
        ease: "none",
        repeat: -1,
      });
    }

    return () => {
      killable.forEach((k) => k.kill());
      bgAnim?.kill();
    };
  }, []);

  return null;
}
