import { IsIn } from 'class-validator';

export class PatchScannerDto {
  @IsIn(['enabled', 'disabled'])
  status!: 'enabled' | 'disabled';
}
