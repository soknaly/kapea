import { Module } from '@nestjs/common';
import { DatabaseModule } from '@kapea/database';
import { QueueModule } from '@kapea/messaging';
import { RedisModule } from '@kapea/redis';
import { StorageModule } from '@kapea/storage';
import { AdminApiKeyGuard } from './admin-api-key.guard';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';

@Module({
  imports: [DatabaseModule, QueueModule, RedisModule, StorageModule],
  controllers: [AdminController],
  providers: [AdminService, AdminApiKeyGuard],
})
export class AdminModule {}
