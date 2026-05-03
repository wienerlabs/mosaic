"use client";

// Terminal.tsx
//
// Mosaic-palette adaptation of MagicUI's terminal component
// (https://magicui.design — MIT licensed). Behavior preserved:
//
//   - <Terminal sequence startOnView> orchestrates child animations
//     so each <TypingAnimation> / <AnimatedSpan> begins exactly
//     when the previous one finishes — no manual `delay` chaining.
//   - <TypingAnimation> types a string character-by-character.
//   - <AnimatedSpan> fades a block in once the previous item is done.
//
// Differences from the upstream snippet:
//
//   1. No Tailwind. Class names are plain CSS hooks (`mtm-*`); the
//      style system lives in `app/globals.css` next to the existing
//      `.mag-*` magazine grammar.
//   2. No `cn()` helper — string template joining is enough for the
//      handful of conditional classes we use.
//   3. No emoji and no Unicode glyphs in the chrome (the request was
//      explicitly emoji-free / symbol-free). The chrome carries a
//      typographic label (`MOSAIC // RUNTIME EVIDENCE`) instead of
//      the macOS three-dot affordance.
//   4. Provenance metadata (commit SHA + capture timestamp + exit
//      code) renders under the chrome, NOT inside the typed area —
//      this preserves the verbatim feel of the typed bytes while
//      still surfacing the cryptographic provenance an enterprise
//      reviewer wants.

import {
  Children,
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  motion,
  useInView,
  type DOMMotionComponents,
  type HTMLMotionProps,
  type MotionProps,
} from "motion/react";

interface SequenceContextValue {
  completeItem: (index: number) => void;
  activeIndex: number;
  sequenceStarted: boolean;
  generation: number;
}

const SequenceContext = createContext<SequenceContextValue | null>(null);
const useSequence = () => useContext(SequenceContext);

const ItemIndexContext = createContext<number | null>(null);
const useItemIndex = () => useContext(ItemIndexContext);

const motionElements = {
  article: motion.article,
  div: motion.div,
  h1: motion.h1,
  h2: motion.h2,
  h3: motion.h3,
  h4: motion.h4,
  h5: motion.h5,
  h6: motion.h6,
  li: motion.li,
  p: motion.p,
  section: motion.section,
  span: motion.span,
} as const;

type MotionElementType = Extract<
  keyof DOMMotionComponents,
  keyof typeof motionElements
>;

interface AnimatedSpanProps extends Omit<MotionProps, "children"> {
  children: ReactNode;
  delay?: number;
  className?: string;
  startOnView?: boolean;
}

export const AnimatedSpan = ({
  children,
  delay = 0,
  className,
  startOnView = false,
  ...props
}: AnimatedSpanProps) => {
  const elementRef = useRef<HTMLDivElement | null>(null);
  const isInView = useInView(elementRef as React.RefObject<Element>, {
    amount: 0.3,
    once: true,
  });

  const sequence = useSequence();
  const itemIndex = useItemIndex();
  const [hasStarted, setHasStarted] = useState(false);
  const [seenGeneration, setSeenGeneration] = useState(-1);

  // When the parent terminal restarts (new generation), reset our
  // local "hasStarted" flag so we replay from scratch.
  useEffect(() => {
    if (!sequence) return;
    if (sequence.generation !== seenGeneration) {
      setHasStarted(false);
      setSeenGeneration(sequence.generation);
    }
  }, [sequence, seenGeneration]);

  useEffect(() => {
    if (!sequence || itemIndex === null) return;
    if (!sequence.sequenceStarted) return;
    if (hasStarted) return;
    if (sequence.activeIndex === itemIndex) {
      setHasStarted(true);
    }
  }, [sequence, hasStarted, itemIndex]);

  const shouldAnimate = sequence ? hasStarted : startOnView ? isInView : true;

  return (
    <motion.div
      ref={elementRef}
      initial={{ opacity: 0, y: -3 }}
      animate={shouldAnimate ? { opacity: 1, y: 0 } : { opacity: 0, y: -3 }}
      transition={{ duration: 0.18, delay: sequence ? 0 : delay / 1000 }}
      className={["mtm-line", className ?? ""].join(" ").trim()}
      onAnimationComplete={() => {
        if (!sequence) return;
        if (itemIndex === null) return;
        sequence.completeItem(itemIndex);
      }}
      {...props}
    >
      {children}
    </motion.div>
  );
};

interface TypingAnimationProps extends Omit<MotionProps, "children"> {
  children: string;
  className?: string;
  duration?: number;
  delay?: number;
  as?: MotionElementType;
  startOnView?: boolean;
}

export const TypingAnimation = ({
  children,
  className,
  duration = 18,
  delay = 0,
  as: Component = "span",
  startOnView = true,
  ...props
}: TypingAnimationProps) => {
  if (typeof children !== "string") {
    throw new Error("TypingAnimation: children must be a string");
  }

  const MotionComponent = motionElements[Component];

  const [displayedText, setDisplayedText] = useState<string>("");
  const [started, setStarted] = useState(false);
  const [seenGeneration, setSeenGeneration] = useState(-1);
  const elementRef = useRef<HTMLElement | null>(null);
  const isInView = useInView(elementRef as React.RefObject<Element>, {
    amount: 0.3,
    once: true,
  });

  const sequence = useSequence();
  const itemIndex = useItemIndex();
  const hasSequence = sequence !== null;
  const sequenceStarted = sequence?.sequenceStarted ?? false;
  const sequenceActiveIndex = sequence?.activeIndex ?? null;
  const sequenceCompleteItemRef = useRef<
    SequenceContextValue["completeItem"] | null
  >(null);
  const sequenceItemIndexRef = useRef<number | null>(null);

  useEffect(() => {
    sequenceCompleteItemRef.current = sequence?.completeItem ?? null;
    sequenceItemIndexRef.current = itemIndex;
  }, [sequence?.completeItem, itemIndex]);

  // Reset on generation change so the same component instance can be
  // re-played with a different children string when the user swaps
  // captures.
  useEffect(() => {
    if (!sequence) return;
    if (sequence.generation !== seenGeneration) {
      setDisplayedText("");
      setStarted(false);
      setSeenGeneration(sequence.generation);
    }
  }, [sequence, seenGeneration]);

  useEffect(() => {
    let startTimeout: ReturnType<typeof setTimeout> | null = null;

    if (hasSequence && itemIndex !== null) {
      if (sequenceStarted && !started && sequenceActiveIndex === itemIndex) {
        setStarted(true);
      }
    } else if (!startOnView || isInView) {
      startTimeout = setTimeout(() => setStarted(true), delay);
    }

    return () => {
      if (startTimeout !== null) clearTimeout(startTimeout);
    };
  }, [
    delay,
    startOnView,
    isInView,
    started,
    hasSequence,
    sequenceActiveIndex,
    sequenceStarted,
    itemIndex,
  ]);

  useEffect(() => {
    let typingEffect: ReturnType<typeof setInterval> | null = null;

    if (started) {
      let i = 0;
      typingEffect = setInterval(() => {
        if (i < children.length) {
          setDisplayedText(children.substring(0, i + 1));
          i++;
        } else {
          if (typingEffect !== null) clearInterval(typingEffect);
          const completeItem = sequenceCompleteItemRef.current;
          const currentItemIndex = sequenceItemIndexRef.current;
          if (completeItem && currentItemIndex !== null) {
            completeItem(currentItemIndex);
          }
        }
      }, duration);
    }

    return () => {
      if (typingEffect !== null) clearInterval(typingEffect);
    };
  }, [children, duration, started]);

  // motion's typed prop union for ref+className is tight enough that
  // a permissive cast keeps the call site readable without losing
  // runtime behavior.
  const TypedComponent = MotionComponent as unknown as (
    p: HTMLMotionProps<"span"> & {
      ref?: React.Ref<HTMLElement>;
    },
  ) => React.ReactElement;

  return (
    <TypedComponent
      ref={elementRef as React.Ref<HTMLElement>}
      className={["mtm-typed", className ?? ""].join(" ").trim()}
      {...props}
    >
      {displayedText}
    </TypedComponent>
  );
};

interface TerminalProps {
  children: ReactNode;
  className?: string;
  sequence?: boolean;
  startOnView?: boolean;
  /** Bumping this restarts every child animation from scratch. */
  generation?: number;
  /** Optional title text rendered in the chrome. No emojis. */
  chromeLabel?: string;
  /** Optional metadata bar shown under the chrome (provenance line). */
  metadata?: ReactNode;
  /** Slot for action buttons rendered above the typed area. */
  toolbar?: ReactNode;
  /** Slot for footer content (e.g. exit code, duration). */
  footer?: ReactNode;
}

export const Terminal = ({
  children,
  className,
  sequence = true,
  startOnView = true,
  generation = 0,
  chromeLabel,
  metadata,
  toolbar,
  footer,
}: TerminalProps) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const isInView = useInView(containerRef as React.RefObject<Element>, {
    amount: 0.3,
    once: true,
  });

  const [activeIndex, setActiveIndex] = useState(0);

  // Restart sequence when `generation` changes (consumer swapped to
  // a different captured run, for instance).
  useEffect(() => {
    setActiveIndex(0);
  }, [generation]);

  const sequenceHasStarted = sequence ? !startOnView || isInView : false;

  const contextValue = useMemo<SequenceContextValue | null>(() => {
    if (!sequence) return null;
    return {
      completeItem: (index: number) => {
        setActiveIndex((current) => (index === current ? current + 1 : current));
      },
      activeIndex,
      sequenceStarted: sequenceHasStarted,
      generation,
    };
  }, [sequence, activeIndex, sequenceHasStarted, generation]);

  const wrappedChildren = useMemo(() => {
    if (!sequence) return children;
    const array = Children.toArray(children);
    return array.map((child, index) => (
      <ItemIndexContext.Provider key={`${generation}-${index}`} value={index}>
        {child as ReactNode}
      </ItemIndexContext.Provider>
    ));
  }, [children, sequence, generation]);

  const content = (
    <div
      ref={containerRef}
      className={["mtm-terminal", className ?? ""].join(" ").trim()}
    >
      <header className="mtm-chrome">
        <span className="mtm-chrome-label">{chromeLabel ?? "MOSAIC // TERMINAL"}</span>
      </header>
      {metadata ? <div className="mtm-meta">{metadata}</div> : null}
      {toolbar ? <div className="mtm-toolbar">{toolbar}</div> : null}
      <pre className="mtm-pre">
        <code className="mtm-code">{wrappedChildren}</code>
      </pre>
      {footer ? <div className="mtm-footer">{footer}</div> : null}
    </div>
  );

  if (!sequence) return content;

  return (
    <SequenceContext.Provider value={contextValue}>
      {content}
    </SequenceContext.Provider>
  );
};
