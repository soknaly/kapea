import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const port = Number(process.env.RESULT_CONSUMER_PORT ?? process.env.PORT ?? 3001);
  await app.listen(port);
  console.log(`KAPEA result-consumer listening on :${port}`);
}

bootstrap();
