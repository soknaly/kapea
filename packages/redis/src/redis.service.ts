import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private client: Redis | null = null;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const url = this.config.get<string>('REDIS_URL', 'redis://localhost:6379');
    this.client = new Redis(url, {
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    await this.client.connect();
    this.logger.log(`Connected to Redis at ${url}`);
  }

  async onModuleDestroy(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      this.client = null;
    }
  }

  getClient(): Redis {
    if (!this.client) {
      throw new Error('Redis client is not connected');
    }
    return this.client;
  }

  async ping(): Promise<string> {
    return this.getClient().ping();
  }

  async incr(key: string): Promise<number> {
    return this.getClient().incr(key);
  }

  async expire(key: string, seconds: number): Promise<number> {
    return this.getClient().expire(key, seconds);
  }

  async get(key: string): Promise<string | null> {
    return this.getClient().get(key);
  }

  async set(
    key: string,
    value: string,
    mode?: 'EX',
    duration?: number,
  ): Promise<'OK' | null> {
    if (mode === 'EX' && duration !== undefined) {
      return this.getClient().set(key, value, 'EX', duration);
    }
    return this.getClient().set(key, value);
  }

  isConnected(): boolean {
    return this.client?.status === 'ready';
  }
}
