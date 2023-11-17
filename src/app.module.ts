import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/prisma.module';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { CustomExceptionFilter } from './common/filters/custom-exception.filter';
import { RequestInterceptor } from './common/interceptors';

export const modules = {
  Auth: AuthModule,
};

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    ...Object.values(modules),
    DatabaseModule,
  ],
  controllers: [],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: RequestInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: CustomExceptionFilter,
    },
  ],
})
export class AppModule {}
