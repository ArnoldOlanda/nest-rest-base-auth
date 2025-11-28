import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { EmailProcessor } from './processors/email.processor';
import { AuthModule } from 'src/auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        connection: {
          host: config.get('REDIS_HOST'),
          port: +(config.get('REDIS_PORT') || 6379),
        },
      }),
    }),
    BullModule.registerQueue({
      name: 'email',
    }),
    AuthModule
  ],
  providers: [EmailProcessor],
  exports: [BullModule],
})
export class QueueModule {}
