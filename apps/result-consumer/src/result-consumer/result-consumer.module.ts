import { Module } from '@nestjs/common';
import { MetricsModule } from '@kapea/observability';
import { ResultConsumerService } from './result-consumer.service';

@Module({
  imports: [MetricsModule],
  providers: [ResultConsumerService],
})
export class ResultConsumerModule {}
