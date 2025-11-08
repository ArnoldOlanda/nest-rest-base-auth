import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { CORS } from './config/cors';
import { FormatResponseInterceptor } from './interceptors/formatResponse.interceptor';
import { HttpExceptionFilter } from './exceptionFilters/httpException.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(morgan('dev'));
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );
  app.useGlobalInterceptors(new FormatResponseInterceptor());
  app.useGlobalFilters(new HttpExceptionFilter())
  app.use(cookieParser());
  app.enableCors(CORS);
  app.setGlobalPrefix('api/v1');

  const config = new DocumentBuilder()
    .addBearerAuth()
    .setTitle('Auth API')
    .setDescription('The Auth API description')
    .setVersion('1.0')
    .addTag('auth')
    .build();
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/v1/docs', app, documentFactory,{
    jsonDocumentUrl: 'api/v1/docs-json',
  });

  await app.listen(process.env.PORT ?? 3000);
  Logger.log(
    `Application is running on: http://localhost:${process.env.PORT ?? 3000}`,
  );
}
bootstrap();
