import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { DatabaseModule } from '@kapea/database';
import { StorageModule } from '@kapea/storage';
import { HealthModule } from './health/health.module';
import { RetentionModule } from './retention/retention.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '../../.env'],
    }),
    ScheduleModule.forRoot(),
    DatabaseModule,
    StorageModule,
    HealthModule,
    RetentionModule,
  ],
})
export class AppModule {}
