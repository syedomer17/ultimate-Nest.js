import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
  Logger,
} from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import mongoose from 'mongoose';
import { LoggerMiddleware } from './middleware/logger.middleware';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import config from './config/config';
// import { MailModule } from './service/mail.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      cache: true,
      load: [config],
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        const uri =
          configService.get<string>('app.MONGODB_URI');

        if (!uri) {
          Logger.error('❌ MONGODB_URI not defined');
          throw new Error('❌ MONGODB_URI not defined');
        }

        await mongoose.connect(uri, {
          serverSelectionTimeoutMS: 5000,
          socketTimeoutMS: 45000,
        });

        mongoose.connection.on('connected', () =>
          Logger.log('✅ MongoDB connected'),
        );
        mongoose.connection.on('disconnected', () =>
          Logger.warn('⚠️ MongoDB disconnected'),
        );
        mongoose.connection.on('reconnected', () =>
          Logger.log('🔁 MongoDB reconnected'),
        );
        mongoose.connection.on('error', (err) =>
          Logger.error(`❌ MongoDB error: ${err}`),
        );

        return { uri };
      },
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        const secret = configService.get<string>('app.jwt.secret');
        if (!secret) {
          Logger.error('❌ JWT_SECRET is not defined');
          throw new Error('JWT_SECRET must be defined');
        }
        Logger.log('✅ JWT Secret loaded');
        return {
          secret,
          signOptions: { expiresIn: '7d' },
        };
      },
    }),
    AuthModule,
    // MailModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LoggerMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}