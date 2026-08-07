import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const SCANNERS = [
  {
    id: 'scanner_clamav',
    engine: 'clamav',
    version: 'unknown',
    status: 'enabled',
    metadataJson: { description: 'ClamAV antivirus engine' },
  },
  {
    id: 'scanner_yara',
    engine: 'yara',
    version: 'dev',
    status: 'enabled',
    metadataJson: { description: 'YARA rule matching engine' },
  },
  {
    id: 'scanner_worker',
    engine: 'rust-worker',
    version: '0.1.0',
    status: 'enabled',
    metadataJson: { description: 'Rust scanning worker orchestrator' },
  },
];

async function main(): Promise<void> {
  for (const scanner of SCANNERS) {
    await prisma.scannerDefinition.upsert({
      where: { engine: scanner.engine },
      create: {
        ...scanner,
        installedAt: new Date(),
      },
      update: {
        status: scanner.status,
        metadataJson: scanner.metadataJson,
      },
    });
  }

  console.log(`Seeded ${SCANNERS.length} scanner definitions`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
