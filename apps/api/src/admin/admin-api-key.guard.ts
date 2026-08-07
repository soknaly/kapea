import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class AdminApiKeyGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const adminKey = request.header('x-admin-key');
    const expectedKey = this.config.get<string>('ADMIN_API_KEY');

    if (!expectedKey || adminKey !== expectedKey) {
      throw new UnauthorizedException('Invalid or missing admin API key');
    }

    return true;
  }
}
