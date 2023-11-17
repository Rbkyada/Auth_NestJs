import { Controller, Post, Body, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ChangePasswordDto,
  LoginDto,
  OTPDto,
  PasswordResetDto,
  RegisterDto,
  VerifyOTPDto,
} from './dto/auth.dto';
import { message } from 'src/common/assets/message.asset';
import { apiDesc } from 'src/common/assets/api-description.asset';
import { ApiOperationResponse } from 'src/common/decorators/api-response.decorator';
import { ApiTags } from '@nestjs/swagger';
import { UserRequestInfo } from 'src/common/decorators/user-request-info.decorator';
import { AuthUserType, RequestInfo } from 'src/common/types';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import { Auth } from 'src/common/decorators/auth.decorator';
import { Role } from '@prisma/client';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperationResponse(
    apiDesc.auth.register,
    HttpStatus.OK,
    message.user.REGISTRATION_SUCCESSFULLY,
  )
  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @ApiOperationResponse(
    apiDesc.auth.verifyUser,
    HttpStatus.OK,
    message.user.VERIFICATION_SUCCESSFULLY,
  )
  @Post('verification')
  async verifyUser(@Body() body: VerifyOTPDto) {
    return this.authService.verifyUser(body);
  }

  @Post('login')
  async login(
    @UserRequestInfo() requestInfo: RequestInfo,
    @Body()
    body: LoginDto,
  ) {
    return this.authService.login(body, requestInfo);
  }

  @Post('forgot-password')
  async forgotPassword(
    @UserRequestInfo() requestInfo: RequestInfo,
    @Body() body: OTPDto,
  ) {
    return this.authService.forgotPassword(body, requestInfo);
  }

  @Auth({
    roles: [Role.admin, Role.user],
  })
  @ApiOperationResponse(
    apiDesc.auth.changePassword,
    HttpStatus.OK,
    message.user.SUCCESS_PASSWORD_CHANGED,
  )
  @Post('change-password')
  async changePassword(
    @Body() body: ChangePasswordDto,
    @CurrentUser() authUser: AuthUserType,
  ) {
    return this.authService.changePassword(authUser, body);
  }

  @ApiOperationResponse(
    apiDesc.auth.resetPassword,
    HttpStatus.OK,
    message.user.SUCCESS_PASSWORD_CHANGED,
  )
  @Post('reset-password')
  async resetPassword(@Body() body: PasswordResetDto) {
    return this.authService.resetPassword(body);
  }

  @ApiOperationResponse(
    apiDesc.auth.verifyOTP,
    HttpStatus.OK,
    message.user.OTP_VERIFIED,
  )
  @Post('verify-otp')
  async verifyOTP(@Body() body: VerifyOTPDto) {
    return this.authService.verifyOTP(body);
  }

  @Auth({
    roles: [Role.admin, Role.user],
  })
  @ApiOperationResponse(
    apiDesc.auth.deleteAccount,
    HttpStatus.OK,
    'User removed successfully',
  )
  @Post('delete-user')
  async deleteUser(@CurrentUser() authUser: AuthUserType) {
    return this.authService.deleteUser(authUser);
  }
}
