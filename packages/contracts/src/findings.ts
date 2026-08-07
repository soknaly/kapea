import { z } from 'zod';

export const ScanFindingSchema = z.object({
  engine: z.string().min(1),
  code: z.string().min(1),
  category: z.string().min(1),
  severity: z.number().int().min(0).max(100),
  confidence: z.number().int().min(0).max(100),
  message: z.string().min(1),
  technicalDetails: z.unknown().optional(),
  pathInsideArchive: z.string().nullable().optional(),
});

export type ScanFinding = z.infer<typeof ScanFindingSchema>;
