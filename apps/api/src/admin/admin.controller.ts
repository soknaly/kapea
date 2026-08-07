import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';
import type { ScanStatus } from '@kapea/contracts';
import { AdminApiKeyGuard } from './admin-api-key.guard';
import { AdminService } from './admin.service';
import { OverrideVerdictDto } from './dto/override-verdict.dto';
import { PatchScannerDto } from './dto/patch-scanner.dto';
import {
  DeployYaraRuleDto,
  ValidateYaraRuleDto,
} from './dto/yara-rule.dto';

@ApiTags('admin')
@ApiSecurity('X-Admin-Key')
@Controller('admin')
@UseGuards(AdminApiKeyGuard)
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Get('scans')
  @ApiOperation({ summary: 'List and search scan jobs' })
  @ApiQuery({ name: 'status', required: false })
  @ApiQuery({ name: 'limit', required: false })
  @ApiQuery({ name: 'cursor', required: false })
  listScans(
    @Query('status') status?: ScanStatus,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ) {
    return this.adminService.listScans({
      status,
      limit: limit ? Number(limit) : undefined,
      cursor,
    });
  }

  @Get('scans/:scanId')
  @ApiOperation({ summary: 'Get full technical scan report' })
  @ApiParam({ name: 'scanId' })
  getScanReport(@Param('scanId') scanId: string) {
    return this.adminService.getScanReport(scanId);
  }

  @Post('scans/:scanId/retry')
  @ApiOperation({ summary: 'Retry a scan job' })
  @ApiParam({ name: 'scanId' })
  retryScan(@Param('scanId') scanId: string, @Req() request: Request) {
    return this.adminService.retryScan(scanId, request.ip);
  }

  @Post('scans/:scanId/override')
  @ApiOperation({ summary: 'Override displayed verdict' })
  @ApiParam({ name: 'scanId' })
  overrideVerdict(
    @Param('scanId') scanId: string,
    @Body() dto: OverrideVerdictDto,
    @Req() request: Request,
  ) {
    return this.adminService.overrideVerdict(scanId, dto, request.ip);
  }

  @Delete('scans/:scanId/file')
  @ApiOperation({ summary: 'Force delete quarantined file' })
  @ApiParam({ name: 'scanId' })
  deleteScanFile(@Param('scanId') scanId: string, @Req() request: Request) {
    return this.adminService.deleteScanFile(scanId, request.ip);
  }

  @Get('scanners')
  @ApiOperation({ summary: 'List scanner definitions' })
  listScanners() {
    return this.adminService.listScanners();
  }

  @Patch('scanners/:engine')
  @ApiOperation({ summary: 'Enable or disable a scanner engine' })
  @ApiParam({ name: 'engine' })
  patchScanner(
    @Param('engine') engine: string,
    @Body() dto: PatchScannerDto,
  ) {
    return this.adminService.patchScanner(engine, dto.status);
  }

  @Get('yara-rules')
  @ApiOperation({ summary: 'List YARA rule file metadata' })
  listYaraRules() {
    return this.adminService.listYaraRules();
  }

  @Post('yara-rules/validate')
  @ApiOperation({ summary: 'Validate YARA rule text' })
  validateYaraRule(@Body() dto: ValidateYaraRuleDto) {
    return this.adminService.validateYaraRule(dto.ruleText);
  }

  @Post('yara-rules/deploy')
  @ApiOperation({ summary: 'Deploy a YARA rule file' })
  deployYaraRule(@Body() dto: DeployYaraRuleDto, @Req() request: Request) {
    return this.adminService.deployYaraRule(dto, request.ip);
  }

  @Get('audit-logs')
  @ApiOperation({ summary: 'List audit logs' })
  @ApiQuery({ name: 'limit', required: false })
  @ApiQuery({ name: 'cursor', required: false })
  listAuditLogs(
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ) {
    return this.adminService.listAuditLogs({
      limit: limit ? Number(limit) : undefined,
      cursor,
    });
  }

  @Get('health')
  @ApiOperation({ summary: 'Detailed admin health check' })
  getAdminHealth() {
    return this.adminService.getAdminHealth();
  }
}
