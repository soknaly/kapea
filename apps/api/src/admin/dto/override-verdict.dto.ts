import { IsEnum, IsString, MinLength } from 'class-validator';
import { Verdict } from '@kapea/contracts';

const VERDICTS = [
  Verdict.CLEAN,
  Verdict.SUSPICIOUS,
  Verdict.MALICIOUS,
  Verdict.UNKNOWN,
  Verdict.SCAN_FAILED,
] as const;

export class OverrideVerdictDto {
  @IsEnum(VERDICTS)
  verdict!: (typeof VERDICTS)[number];

  @IsString()
  @MinLength(1)
  reason!: string;
}
