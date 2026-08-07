//! Threat labels derived from engine detection names.

import { z } from 'zod';

export const ThreatDetectionSchema = z.object({
  engine: z.string().min(1),
  raw: z.string().min(1),
  threatType: z.string().min(1).optional(),
  family: z.string().min(1).optional(),
  label: z.string().min(1).optional(),
});

export type ThreatDetection = z.infer<typeof ThreatDetectionSchema>;

export const ThreatLabelsSchema = z.object({
  popularThreatLabel: z.string().min(1).nullable().optional(),
  threatCategories: z.array(z.string().min(1)).default([]),
  familyLabels: z.array(z.string().min(1)).default([]),
  detections: z.array(ThreatDetectionSchema).default([]),
});

export type ThreatLabels = z.infer<typeof ThreatLabelsSchema>;
