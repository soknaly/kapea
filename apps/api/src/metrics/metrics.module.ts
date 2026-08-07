import { Module } from '@nestjs/common';
import { MetricsModule } from '@kapea/observability';
import { MetricsController } from './metrics.controller';

@Module({
  imports: [MetricsModule],
  controllers: [MetricsController],
})
export class ApiMetricsModule {}
