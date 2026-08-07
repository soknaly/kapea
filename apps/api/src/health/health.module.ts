import { Module } from '@nestjs/common';
import { DatabaseModule } from '@kapea/database';
import { QueueModule } from '@kapea/messaging';
import { RedisModule } from '@kapea/redis';
import { StorageModule } from '@kapea/storage';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

@Module({
  imports: [DatabaseModule, RedisModule, QueueModule, StorageModule],
  controllers: [HealthController],
  providers: [HealthService],
})
export class HealthModule {}
