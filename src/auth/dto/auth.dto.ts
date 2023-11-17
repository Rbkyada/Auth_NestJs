import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  Matches,
} from 'class-validator';
import { message } from 'src/common/assets/message.asset';

export class LoginDto {
  @ApiProperty({
    default: 'admin@gmail.com',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @IsEmail({}, { message: message.validate.email })
  email: 'string';

  @ApiProperty({
    default: 'Admin@123',
  })
  @IsNotEmpty()
  @IsString()
  password: string;
}

export class RegisterDto {
  @ApiProperty({
    default: 'John',
  })
  @IsNotEmpty()
  @IsString()
  @Length(2, 255)
  firstName: string;

  @ApiProperty({
    default: 'Doe',
  })
  @IsNotEmpty()
  @IsString()
  @Length(2, 255)
  lastName: string;

  @ApiProperty({
    default: 'johndoe',
  })
  @IsNotEmpty()
  @IsString()
  @Length(2, 255)
  username: string;

  @ApiProperty({
    default: 'user@gmail.com',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @IsEmail({}, { message: message.validate.email })
  email: string;

  @ApiProperty({
    default: 'Admin@123',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @Matches(/^(?=.*\d)(?=.*[!@#$%.^&*])(?=.*[a-z])(?=.*[A-Z]).{6,}$/, {
    message: message.validate.password,
  })
  password: string;
}

export class OTPDto {
  @ApiProperty({
    default: 'admin@gmail.com',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @IsEmail({}, { message: message.validate.email })
  email: string;
}

export class VerifyOTPDto extends OTPDto {
  @ApiProperty({
    default: '1234',
  })
  @IsNotEmpty()
  @IsString()
  otp: string;
}

export class ChangePasswordDto {
  @ApiProperty({
    default: 'Admin@123',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^(?=.*\d)(?=.*[!@#$%.^&*])(?=.*[a-z])(?=.*[A-Z]).{6,}$/, {
    message: message.validate.password,
  })
  currentPassword: string;

  @ApiProperty({
    default: 'Admin@123',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @Matches(/^(?=.*\d)(?=.*[!@#$%.^&*])(?=.*[a-z])(?=.*[A-Z]).{6,}$/, {
    message: message.validate.password,
  })
  newPassword: string;
}
export class PasswordResetDto {
  @ApiProperty({
    default: 'admin@gmail.com',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @IsEmail({}, { message: message.validate.email })
  email: string;

  @ApiProperty({
    default: '1234',
  })
  @IsNotEmpty()
  @IsString()
  otp: string;

  @ApiProperty({
    default: 'Admin@123',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @Matches(/^(?=.*\d)(?=.*[!@#$%.^&*])(?=.*[a-z])(?=.*[A-Z]).{6,}$/, {
    message: message.validate.password,
  })
  password: string;
}

export class DeleteUserDto {
  @ApiProperty({
    default: 'admin@gmail.com',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 255)
  @IsEmail({}, { message: message.validate.email })
  email: string;
}
