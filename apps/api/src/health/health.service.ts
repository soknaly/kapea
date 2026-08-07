import { Injectable } from '@nestjs/common';
import { PrismaService } from '@kapea/database';
import { QueueService } from '@kapea/messaging';
import { RedisService } from '@kapea/redis';
import { StorageService } from '@kapea/storage';

type CheckStatus = 'ok' | 'error';

interface ReadinessChecks {
  postgres: CheckStatus;
  redis: CheckStatus;
  queue: CheckStatus;
  storage: CheckStatus;
}

export interface ReadinessResponse {
  status: 'ok' | 'degraded';
  checks: ReadinessChecks;
}

@Injectable()
export class HealthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly queue: QueueService,
    private readonly storage: StorageService,
  ) {}

  live() {
    return { status: 'ok' };
  }

  async ready(): Promise<ReadinessResponse> {
    const checks: ReadinessChecks = {
      postgres: 'error',
      redis: 'error',
      queue: 'error',
      storage: 'error',
    };

    try {
      await this.prisma.$queryRaw`SELECT 1`;
      checks.postgres = 'ok';
    } catch {
      checks.postgres = 'error';
    }

    try {
      const pong = await this.redis.ping();
      checks.redis = pong === 'PONG' ? 'ok' : 'error';
    } catch {
      checks.redis = 'error';
    }

    checks.queue = (await this.queue.isConnected()) ? 'ok' : 'error';

    try {
      const bucket = this.storage.getDefaultBucket();
      await this.storage.ensureBucket(bucket);
      checks.storage = 'ok';
    } catch {
      checks.storage = 'error';
    }

    const allOk = Object.values(checks).every((status) => status === 'ok');

    return {
      status: allOk ? 'ok' : 'degraded',
      checks,
    };
  }

  scanners() {
    return {
      status: 'ok',
      scanners: [],
    };
  }
}
