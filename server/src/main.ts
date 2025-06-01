import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { LoggerMiddleware } from './middleware/logger.middleware';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser'

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Apply global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      errorHttpStatusCode: 400,
    }),
  );
   app.use(cookieParser());
  // Apply LoggerMiddleware globally
  const loggerMiddleware = new LoggerMiddleware();
  app.use(loggerMiddleware.use);
  
  await app.listen(process.env.PORT ?? 5000);
  Logger.log(`🚀 Application is running on: http://localhost:5000`)
}
bootstrap();