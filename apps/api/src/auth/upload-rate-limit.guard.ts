import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '@kapea/redis';
import type { Request } from 'express';

/**
 * Sliding-window rate limit for uploads keyed by client IP (or X-API-Key).
 */
@Injectable()
export class UploadRateLimitGuard implements CanActivate {
  constructor(
    private readonly redis: RedisService,
    private readonly config: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const max = Number(this.config.get<string>('UPLOAD_RATE_LIMIT', '30'));
    const windowSec = Number(
      this.config.get<string>('UPLOAD_RATE_WINDOW_SECONDS', '60'),
    );

    if (max <= 0) {
      return true;
    }

    const req = context.switchToHttp().getRequest<Request>();
    const apiKey = req.header('x-api-key');
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.ip ||
      'unknown';
    const key = `ratelimit:upload:${apiKey || ip}`;

    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.expire(key, windowSec);
    }

    if (count > max) {
      throw new HttpException(
        'Upload rate limit exceeded. Try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }
}
