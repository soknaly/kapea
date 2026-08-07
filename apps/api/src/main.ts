import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { json } from 'express';
import * as Sentry from '@sentry/node';
import { AppModule } from './app.module';

async function bootstrap() {
  if (process.env.SENTRY_DSN) {
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV ?? 'development',
      tracesSampleRate: Number(process.env.SENTRY_TRACES_SAMPLE_RATE ?? '0.1'),
    });
  }

  const app = await NestFactory.create(AppModule, {
    bodyParser: false,
  });

  app.use(json({ limit: '1mb' }));

  const isDev = (process.env.NODE_ENV ?? 'development') !== 'production';
  app.enableCors({
    origin: isDev
      ? [
          'http://localhost:5173',
          'http://127.0.0.1:5173',
          'http://localhost:3000',
          'http://127.0.0.1:3000',
          'http://localhost:3010',
          'http://127.0.0.1:3010',
        ]
      : false,
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  app.setGlobalPrefix('api/v1', {
    exclude: ['health/(.*)', 'metrics'],
  });

  const swaggerConfig = new DocumentBuilder()
    .setTitle('KAPEA API')
    .setDescription('Secure file malware scanning platform')
    .setVersion('1.0')
    .addApiKey(
      {
        type: 'apiKey',
        name: 'X-API-Key',
        in: 'header',
        description: 'Optional API key when REQUIRE_API_KEY=true',
      },
      'X-API-Key',
    )
    .addApiKey(
      {
        type: 'apiKey',
        name: 'X-Admin-Key',
        in: 'header',
        description: 'Admin API key (ADMIN_API_KEY)',
      },
      'X-Admin-Key',
    )
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, document);

  const port = Number(process.env.API_PORT ?? 3000);
  const host = process.env.API_HOST ?? '127.0.0.1';
  await app.listen(port, host);
  console.log(`KAPEA API listening on http://${host}:${port}`);
}

bootstrap();
