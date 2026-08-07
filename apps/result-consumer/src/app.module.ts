import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from '@kapea/database';
import { QueueModule } from '@kapea/messaging';
import { ObservabilityModule, MetricsModule } from '@kapea/observability';
import { HealthModule } from './health/health.module';
import { ResultConsumerModule } from './result-consumer/result-consumer.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '../../.env'],
    }),
    ObservabilityModule,
    MetricsModule,
    DatabaseModule,
    QueueModule,
    HealthModule,
    ResultConsumerModule,
  ],
})
export class AppModule {}
