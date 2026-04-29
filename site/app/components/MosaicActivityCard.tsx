"use client";

/**
 * @author: @kokonutui (original Apple Activity Card)
 * @adapted: Mosaic palette port — Tailwind → plain CSS, monochrome
 *           blue rings, fitness-metric labels swapped for project-
 *           completion metrics (MAINNET / AUDIT-GATES / TESTS) so
 *           the card visualizes the same "% bitti" answer the
 *           project-status section gives in prose.
 * @license: MIT
 */

import { motion } from "motion/react";

import "./MosaicActivityCard.css";

interface ActivityData {
  label: string;
  /** 0–100 ring fill percentage. */
  value: number;
  /** Outer-to-inner ring color. */
  color: string;
  /** Gradient endpoint (lighter shade for a soft inner-edge fade). */
  colorEnd: string;
  /** Diameter in px. */
  size: number;
  /** Display numerator. */
  current: number;
  /** Display denominator. */
  target: number;
  /** Display unit. */
  unit: string;
  /** Optional one-line subtitle under the label. */
  subtitle?: string;
}

interface CircleProgressProps {
  data: ActivityData;
  index: number;
}

/**
 * Mosaic project-completion metrics — these mirror the prose breakdown
 * in the README/AUDIT.md status snapshots:
 *
 *   MAINNET     — verifiers production-ready / total      = 2/6
 *   AUDIT-GATES — ADR-0006 audit gates landed / total     = 6/6
 *   TESTS       — current lib tests / target              = 642/700
 *
 * Bump these when the underlying numbers change. The ring fill
 * percentage (value) is computed from `current/target`.
 */
const activities: ActivityData[] = [
  {
    label: "MAINNET",
    subtitle: "Production-ready verifiers",
    value: 33,
    color: "#112d4e",
    colorEnd: "#1f4670",
    size: 200,
    current: 2,
    target: 6,
    unit: "VERIFIERS",
  },
  {
    label: "AUDIT-GATES",
    subtitle: "ADR-0006 coverage",
    value: 100,
    color: "#3f72af",
    colorEnd: "#6e9cee",
    size: 160,
    current: 6,
    target: 6,
    unit: "GATES",
  },
  {
    label: "TESTS",
    subtitle: "Workspace lib coverage",
    value: 92,
    color: "#6e9cee",
    colorEnd: "#a8c4f0",
    size: 120,
    current: 642,
    target: 700,
    unit: "TESTS",
  },
];

const CircleProgress = ({ data, index }: CircleProgressProps) => {
  const strokeWidth = 16;
  const radius = (data.size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const progress = ((100 - data.value) / 100) * circumference;

  const gradientId = `mosaic-activity-gradient-${data.label.toLowerCase()}`;
  const gradientUrl = `url(#${gradientId})`;

  return (
    <motion.div
      animate={{ opacity: 1, scale: 1 }}
      className="mosaic-activity-ring-slot"
      initial={{ opacity: 0, scale: 0.8 }}
      transition={{ duration: 0.8, delay: index * 0.2, ease: "easeOut" }}
    >
      <div className="mosaic-activity-ring-positioner">
        <svg
          aria-label={`${data.label} progress — ${data.value}%`}
          className="mosaic-activity-svg"
          height={data.size}
          viewBox={`0 0 ${data.size} ${data.size}`}
          width={data.size}
        >
          <title>{`${data.label} progress — ${data.value}%`}</title>

          <defs>
            <linearGradient id={gradientId} x1="0%" x2="100%" y1="0%" y2="100%">
              <stop offset="0%" stopColor={data.color} stopOpacity={1} />
              <stop offset="100%" stopColor={data.colorEnd} stopOpacity={1} />
            </linearGradient>
          </defs>

          {/* Track ring (background channel). Subtle so the foreground
           * gradient ring reads as the active value. */}
          <circle
            className="mosaic-activity-track"
            cx={data.size / 2}
            cy={data.size / 2}
            fill="none"
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
          />

          {/* Progress ring (animated value fill). */}
          <motion.circle
            animate={{ strokeDashoffset: progress }}
            cx={data.size / 2}
            cy={data.size / 2}
            fill="none"
            initial={{ strokeDashoffset: circumference }}
            r={radius}
            stroke={gradientUrl}
            strokeDasharray={circumference}
            strokeLinecap="round"
            strokeWidth={strokeWidth}
            style={{
              filter: "drop-shadow(0 0 6px rgba(17, 45, 78, 0.18))",
            }}
            transition={{
              duration: 1.8,
              delay: index * 0.2,
              ease: "easeInOut",
            }}
          />
        </svg>
      </div>
    </motion.div>
  );
};

const DetailedActivityInfo = () => {
  return (
    <motion.div
      animate={{ opacity: 1, x: 0 }}
      className="mosaic-activity-details"
      initial={{ opacity: 0, x: 20 }}
      transition={{ duration: 0.5, delay: 0.3 }}
    >
      {activities.map((activity) => (
        <motion.div
          className="mosaic-activity-detail-row"
          key={activity.label}
        >
          <span className="mosaic-activity-detail-label">
            {activity.label}
            {activity.subtitle ? (
              <span className="mosaic-activity-detail-subtitle">
                {activity.subtitle}
              </span>
            ) : null}
          </span>
          <span
            className="mosaic-activity-detail-value"
            style={{ color: activity.color }}
          >
            {activity.current}/{activity.target}
            <span className="mosaic-activity-detail-unit">
              {activity.unit}
            </span>
          </span>
        </motion.div>
      ))}
    </motion.div>
  );
};

export interface MosaicActivityCardProps {
  title?: string;
  className?: string;
}

export default function MosaicActivityCard({
  title = "Project Completion",
  className = "",
}: MosaicActivityCardProps) {
  const rootClass = ["mosaic-activity-root", className]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={rootClass}>
      <div className="mosaic-activity-stack">
        <motion.h2
          animate={{ opacity: 1, y: 0 }}
          className="mosaic-activity-title"
          initial={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.5 }}
        >
          {title}
        </motion.h2>

        <div className="mosaic-activity-body">
          <div className="mosaic-activity-rings">
            {activities.map((activity, index) => (
              <CircleProgress
                data={activity}
                index={index}
                key={activity.label}
              />
            ))}
          </div>
          <DetailedActivityInfo />
        </div>
      </div>
    </div>
  );
}
