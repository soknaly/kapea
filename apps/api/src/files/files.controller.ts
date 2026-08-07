import {
  Controller,
  Post,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';
import { ApiKeyGuard } from '../auth/api-key.guard';
import { UploadRateLimitGuard } from '../auth/upload-rate-limit.guard';
import { FilesService, ScanUploadResponse } from './files.service';

@ApiTags('files')
@Controller('files')
export class FilesController {
  constructor(private readonly filesService: FilesService) {}

  @Post('scan')
  @HttpCode(HttpStatus.ACCEPTED)
  @UseGuards(ApiKeyGuard, UploadRateLimitGuard)
  @ApiSecurity('X-API-Key')
  @ApiOperation({ summary: 'Upload a file for malware scanning' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      required: ['file'],
      properties: {
        file: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @ApiResponse({ status: 202, description: 'File accepted and queued' })
  async scanFile(@Req() request: Request): Promise<ScanUploadResponse> {
    return this.filesService.handleScanUpload(request);
  }
}
