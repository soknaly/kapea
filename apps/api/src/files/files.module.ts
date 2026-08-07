import { Module } from '@nestjs/common';
import { DatabaseModule } from '@kapea/database';
import { QueueModule } from '@kapea/messaging';
import { RedisModule } from '@kapea/redis';
import { StorageModule } from '@kapea/storage';
import { AuthModule } from '../auth/auth.module';
import { UploadRateLimitGuard } from '../auth/upload-rate-limit.guard';
import { FilesController } from './files.controller';
import { FilesService } from './files.service';

@Module({
  imports: [
    AuthModule,
    DatabaseModule,
    QueueModule,
    RedisModule,
    StorageModule,
  ],
  controllers: [FilesController],
  providers: [FilesService, UploadRateLimitGuard],
})
export class FilesModule {}
