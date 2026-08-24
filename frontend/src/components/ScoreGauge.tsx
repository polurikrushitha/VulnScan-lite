// VulnScan Lite — Score Gauge & Donut Visualization

import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import type { Grade } from '../types';

interface ScoreGaugeProps {
  score: number;
  grade?: Grade;
}

export const getGradeColor = (grade?: string): string => {
  if (!grade) return '#94a3b8';
  if (grade === 'A') return '#22c55e';
  if (grade === 'B+') return '#84cc16';
  if (grade === 'B') return '#a3e635';
  if (grade === 'C') return '#facc15';
  if (grade === 'D') return '#f97316';
  return '#ef4444';
};

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, grade }) => {
  const safeScore = Math.max(0, Math.min(100, score));
  const primaryColor = getGradeColor(grade);

  const data = [
    { name: 'Score', value: safeScore, color: primaryColor },
    { name: 'Remaining', value: 100 - safeScore, color: 'rgba(255, 255, 255, 0.08)' },
  ];

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        width: '180px',
        height: '180px',
        margin: '0 auto',
      }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            startAngle={225}
            endAngle={-45}
            innerRadius={58}
            outerRadius={78}
            paddingAngle={0}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>

      {/* Centered Score & Grade Overlay */}
      <div
        style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
          pointerEvents: 'none',
        }}
      >
        <div style={{ fontSize: '2.25rem', fontWeight: 800, lineHeight: 1, color: 'var(--color-text)' }}>
          {safeScore.toFixed(0)}
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>
          out of 100
        </div>
        {grade && (
          <div
            style={{
              marginTop: '4px',
              fontSize: '1rem',
              fontWeight: 800,
              color: primaryColor,
              textShadow: `0 0 12px ${primaryColor}40`,
            }}
          >
            Grade {grade}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScoreGauge;
