import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from '@kapea/database';
import { QueueModule } from '@kapea/messaging';
import { RedisModule } from '@kapea/redis';
import { StorageModule } from '@kapea/storage';
import { AuthModule } from './auth/auth.module';
import { FilesModule } from './files/files.module';
import { HealthModule } from './health/health.module';
import { AdminModule } from './admin/admin.module';
import { ApiMetricsModule } from './metrics/metrics.module';
import { ScansModule } from './scans/scans.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '../../.env'],
    }),
    DatabaseModule,
    RedisModule,
    StorageModule,
    QueueModule,
    AuthModule,
    HealthModule,
    FilesModule,
    ScansModule,
    AdminModule,
    ApiMetricsModule,
  ],
})
export class AppModule {}
