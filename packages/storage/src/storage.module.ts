import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { createObjectStorage } from './storage.factory';
import { StorageService } from './storage.service';
import { OBJECT_STORAGE } from './storage.types';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: OBJECT_STORAGE,
      inject: [ConfigService],
      useFactory: (config: ConfigService) => createObjectStorage(config),
    },
    StorageService,
  ],
  exports: [StorageService, OBJECT_STORAGE],
})
export class StorageModule {}
