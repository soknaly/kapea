import { IsOptional, IsString, MinLength } from 'class-validator';

export class ValidateYaraRuleDto {
  @IsString()
  @MinLength(1)
  ruleText!: string;
}

export class DeployYaraRuleDto {
  @IsString()
  @MinLength(1)
  ruleText!: string;

  @IsString()
  @MinLength(1)
  filename!: string;

  @IsOptional()
  @IsString()
  version?: string;
}
