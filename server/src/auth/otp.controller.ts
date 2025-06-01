import { Controller, Post, Body } from '@nestjs/common';
import { OtpService } from './otp.service';

@Controller('otp')
export class OtpController {
  constructor(private readonly otpService: OtpService) {}

  // Request OTP generation & send email
  @Post('send')
  async sendOtp(@Body('email') email: string) {
    return this.otpService.generateOtp(email);
  }

  // Verify OTP
  @Post('verify')
  async verifyOtp(@Body() body: { email: string; code: string }) {
    const { email, code } = body;
    return this.otpService.verifyOtp(email, code);
  }
}