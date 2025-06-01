import { IsString, MinLength, Matches, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
  @ApiProperty({
    description: 'Token received by the user to reset their password',
    example: 'abc123resetToken',
  })
  @IsString()
  @IsNotEmpty()
  resetToken: string;

  @ApiProperty({
    description: 'New password with at least 6 characters and one number',
    example: 'newpass123',
  })
  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9]).+$/, {
    message: 'Password must contain at least one number',
  })
  @IsNotEmpty()
  newPassword: string;
}
