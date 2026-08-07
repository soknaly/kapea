import { Controller, Get, Header } from '@nestjs/common';
import { MetricsService } from '@kapea/observability';

@Controller()
export class MetricsController {
  constructor(private readonly metrics: MetricsService) {}

  @Get('metrics')
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  async metricsEndpoint(): Promise<string> {
    return this.metrics.render();
  }
}
