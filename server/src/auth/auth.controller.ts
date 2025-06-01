import {
  Controller,
  Put,
  Body,
  UseGuards,
  Req,
  Post,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { Request, Response } from 'express';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthenticationGuard } from 'src/guards/auth.guards';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('signup')
    async signup(@Body() signupData: SignupDto) {
        return this.authService.signup(signupData);
    }

     @Post('login')
  async login(
    @Body() credentials: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { accessToken, refreshToken, user } =
      await this.authService.login(credentials);

    response.cookie('accessToken', accessToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 day
      sameSite: 'lax',
    });

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'lax',
    });
    
    return { user, accessToken, refreshToken };
  }

    @Post('refresh')
async refreshToken(
  @Body() refreshTokenDto: RefreshTokenDto,
  @Res({ passthrough: true }) response: Response,
) {
  // Assuming your authService.refreshToken returns new tokens
  const { accessToken, refreshToken } = await this.authService.refreshToken(refreshTokenDto.refreshToken);

  // Set the updated tokens as cookies again
  response.cookie('accessToken', accessToken, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    sameSite: 'lax',
  });

  response.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    sameSite: 'lax',
  });

  // Return the tokens in the response JSON
  return {
    message: 'Tokens refreshed',
    accessToken,
    refreshToken,
  };
}

  @Put('change-password')
  @UseGuards(AuthenticationGuard)
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() req: Request & { userId?: string },
  ) {
    if (!req.userId) {
      throw new UnauthorizedException('User ID missing from request');
    }

    await this.authService.changePassword(
      req.userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
    );

    return { message: 'Password changed successfully' };
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Put('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    await this.authService.resetPassword(
      resetPasswordDto.newPassword,
      resetPasswordDto.resetToken,
    );
    return { message: 'Password reset successfully' };
  }

  @Post('verify-email')
  async verifyEmail(@Body('email') email: string, @Body('code') code: string) {
    return this.authService.verifyEmail(email, code);
  }
  
  @Post('logout')
  async logout(@Res({ passthrough: true }) response: Response) {
    // Clear the cookies by setting them to empty with immediate expiry
    response.clearCookie('accessToken', {
      httpOnly: true,
      sameSite: 'lax',
    });

    response.clearCookie('refreshToken', {
      httpOnly: true,
      sameSite: 'lax',
    });

    return { message: 'Logged out successfully' };
  }
}
