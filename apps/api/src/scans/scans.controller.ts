import {
  Controller,
  Delete,
  Get,
  Param,
  Req,
} from '@nestjs/common';
import {
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';
import {
  ScanResultResponse,
  ScanStatusResponse,
  ScansService,
} from './scans.service';

@ApiTags('scans')
@Controller('scans')
export class ScansController {
  constructor(private readonly scansService: ScansService) {}

  @Get(':scanId')
  @ApiOperation({ summary: 'Get scan status and progress' })
  @ApiParam({ name: 'scanId', description: 'Scan identifier' })
  @ApiResponse({ status: 200, description: 'Scan status' })
  @ApiResponse({ status: 404, description: 'Scan not found' })
  getScanStatus(@Param('scanId') scanId: string): Promise<ScanStatusResponse> {
    return this.scansService.getScanStatus(scanId);
  }

  @Get(':scanId/result')
  @ApiOperation({ summary: 'Get scan result' })
  @ApiParam({ name: 'scanId', description: 'Scan identifier' })
  @ApiResponse({ status: 200, description: 'Scan result' })
  @ApiResponse({ status: 404, description: 'Result not available' })
  getScanResult(@Param('scanId') scanId: string): Promise<ScanResultResponse> {
    return this.scansService.getScanResult(scanId);
  }

  @Delete(':scanId/file')
  @ApiOperation({ summary: 'Delete quarantined file for a scan' })
  @ApiParam({ name: 'scanId', description: 'Scan identifier' })
  @ApiResponse({ status: 200, description: 'File deleted' })
  @ApiResponse({ status: 404, description: 'Scan not found' })
  deleteScanFile(
    @Param('scanId') scanId: string,
    @Req() request: Request,
  ) {
    const ipAddress = request.ip;
    return this.scansService.deleteScanFile(scanId, ipAddress);
  }
}
