import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { HealthService, ReadinessResponse } from './health.service';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(private readonly health: HealthService) {}

  @Get('live')
  @ApiOperation({ summary: 'Liveness probe' })
  live() {
    return this.health.live();
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe' })
  ready(): Promise<ReadinessResponse> {
    return this.health.ready();
  }

  @Get('scanners')
  @ApiOperation({ summary: 'Scanner health status' })
  scanners() {
    return this.health.scanners();
  }
}
