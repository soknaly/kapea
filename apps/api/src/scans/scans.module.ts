import { Module } from '@nestjs/common';
import { DatabaseModule } from '@kapea/database';
import { StorageModule } from '@kapea/storage';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';

@Module({
  imports: [DatabaseModule, StorageModule],
  controllers: [ScansController],
  providers: [ScansService],
})
export class ScansModule {}
