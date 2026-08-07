import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const requireApiKey =
      this.config.get<string>('REQUIRE_API_KEY', 'false') === 'true';
    if (!requireApiKey) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const apiKey = request.header('x-api-key');
    const expectedKey = this.config.get<string>('API_KEY');

    if (!expectedKey || apiKey !== expectedKey) {
      throw new UnauthorizedException('Invalid or missing API key');
    }

    return true;
  }
}
