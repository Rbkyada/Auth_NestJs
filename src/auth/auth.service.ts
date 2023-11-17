import { ForbiddenException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/database/prisma.service';
import { LoginResponse, UserForToken } from './types';
import { Algorithm, AuthUserType, RequestInfo, Tokens } from 'src/common/types';
import {
  ChangePasswordDto,
  LoginDto,
  OTPDto,
  PasswordResetDto,
  RegisterDto,
  VerifyOTPDto,
} from './dto/auth.dto';
import { message } from 'src/common/assets/message.asset';
import { AuthTransformer } from './auth.transformer';
import { Prisma, User } from '@prisma/client';
import { Actions } from 'src/common/assets/constant.asset';

@Injectable()
export class AuthService {
  private readonly saltRounds: number = 10;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly authTransformer: AuthTransformer,
  ) {}

  async deleteUser(authUserType: AuthUserType) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: authUserType.id,
      },
      select: {
        id: true,
      },
    });

    await this.prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        email: authUserType.email + '#' + new Date().toUTCString(),
      },
    });

    await this.prisma.user.delete({
      where: {
        id: user.id,
      },
    });
  }

  async login(body: LoginDto, requestInfo: RequestInfo) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
      select: {
        id: true,
        first_name: true,
        last_name: true,
        username: true,
        email: true,
        role: true,
        logo: true,
        is_verified: true,
        is_onboarded: true,
        is_social_register: true,
        password: true,
        provider: true,
        provider_id: true,
      },
    });

    if (!user) {
      throw new ForbiddenException(message.user.INVALID_CRED);
    }

    return this.loginResponse(body, user, requestInfo);
  }

  async forgotPassword(body: OTPDto, requestInfo: RequestInfo) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
      select: {
        id: true,
        is_onboarded: true,
        is_verified: true,
        is_social_register: true,
      },
    });

    if (!user) {
      throw new ForbiddenException(message.user.USER_NOT_FOUND);
    }

    // if (!user?.is_onboarded) {
    //   throw new ForbiddenException(message.user.USER_NOT_ONBOARDED);
    // }

    if (!user?.is_verified) {
      throw new ForbiddenException(message.user.USER_NOT_VERIFIED);
    }

    const newOTP: number = this.generateOTP();

    await this.prisma.user.update({
      data: {
        code: newOTP.toString(),
      },
      where: {
        id: user.id,
      },
    });

    await this.prisma.log.create({
      data: {
        user_id: user.id,
        action_id: Actions.FORGOT_PASSWORD,
        request_data: requestInfo as Prisma.JsonValue,
      },
    });

    return {
      otp: newOTP,
    };
  }

  async changePassword(userData: AuthUserType, body: ChangePasswordDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userData.id,
      },
      select: {
        id: true,
        password: true,
      },
    });

    if (user.password !== null) {
      const isValidPassword = await bcrypt.compare(
        body.currentPassword,
        user.password,
      );

      if (body.currentPassword === body.newPassword) {
        throw new ForbiddenException(message.user.SAME_PASSWORD);
      }

      if (!isValidPassword) {
        throw new ForbiddenException(message.user.INVALID_CURRENT_PASSWORD);
      }
    }
    await this.prisma.user.update({
      where: {
        id: userData.id,
      },
      data: {
        password: await bcrypt.hash(body.newPassword, this.saltRounds),
      },
    });

    await this.prisma.log.create({
      data: {
        user_id: userData.id,
        action_id: Actions.RESET_PASSWORD,
      },
    });
  }

  async verifyOTP(body: VerifyOTPDto) {
    await this.otpValidate(body);
  }

  async resetPassword(body: PasswordResetDto) {
    const user = await this.otpValidate(body);
    if (user) {
      if (user.password !== null) {
        if (await bcrypt.compare(body.password, user.password)) {
          throw new ForbiddenException(message.user.USE_DIFFERENT_PASSWORD);
        }
      }

      await this.prisma.user.update({
        where: {
          email: body.email,
        },
        data: {
          password: await bcrypt.hash(body.password, this.saltRounds),
          code: null,
        },
      });

      await this.prisma.log.create({
        data: {
          user_id: user.id,
          action_id: Actions.RESET_PASSWORD,
        },
      });
    }
  }

  private async loginResponse(
    body: LoginDto,
    user: Partial<User>,
    requestInfo: RequestInfo,
  ): Promise<LoginResponse> {
    const isValidPassword = await bcrypt.compare(body.password, user.password);

    if (!isValidPassword) {
      throw new ForbiddenException(message.user.INVALID_CRED);
    }

    const { access_token }: Tokens = await this.getToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    await this.prisma.log.create({
      data: {
        user_id: user.id,
        action_id: Actions.LOGIN,
        request_data: requestInfo as Prisma.JsonValue,
      },
    });

    return {
      user: this.authTransformer.transformUser(user),
      access_token,
    };
  }

  async verifyUser(body: VerifyOTPDto) {
    const validate = await this.otpValidate(body);

    if (validate) {
      await this.prisma.user.update({
        where: {
          email: body.email,
        },
        data: {
          is_verified: true,
          code: null,
        },
      });
    }
  }

  async register(body: RegisterDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
    });

    if (user) {
      throw new ForbiddenException(message.user.USER_ALREADY_EXISTS);
    } else {
      const newOTP: number = this.generateOTP();

      await this.prisma.user.create({
        data: {
          first_name: body.firstName,
          last_name: body.lastName,
          email: body.email,
          username: body.username,
          code: newOTP.toString(),
          password: await bcrypt.hash(body.password, this.saltRounds),
        },
      });
    }

    const newUser = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
      select: {
        id: true,
        is_onboarded: true,
        role: true,
        email: true,
        username: true,
        logo: true,
        is_verified: true,
        is_social_register: true,
        password: true,
        provider: true,
        provider_id: true,
      },
    });

    return {
      user: this.authTransformer.transformUser(newUser),
      access_token: await this.getToken(newUser),
    };
  }

  private async otpValidate(body: VerifyOTPDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
      select: {
        id: true,
        code: true,
        password: true,
      },
    });

    if (!user) {
      throw new ForbiddenException(message.user.INVALID_REQUEST);
    }

    if (user?.code !== body.otp) {
      throw new ForbiddenException(message.user.INVALID_OTP);
    }

    await this.prisma.log.create({
      data: {
        user_id: user.id,
        action_id: Actions.OTP_VERIFY,
      },
    });

    return user;
  }

  private generateOTP = (): number => {
    return Math.floor(1000 + Math.random() * 9000);
  };

  private async getToken(data: UserForToken): Promise<Tokens> {
    const [at] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: data.id,
          email: data.email,
          role: data.role,
        },
        {
          secret: this.configService.getOrThrow<string>('ACCESS_TOKEN_SECRET'),
          expiresIn: this.configService.getOrThrow<string>(
            'ACCESS_TOKEN_EXPIRES_IN',
          ),
          algorithm: this.configService.getOrThrow<string>(
            'JWT_ALGORITHM',
          ) as Algorithm,
        },
      ),
    ]);

    return {
      access_token: at,
    };
  }
}
