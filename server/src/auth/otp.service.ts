import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Otp, OtpDocument } from './schemas/otp.schema';
import { MailService } from 'src/service/mail.service';

@Injectable()
export class OtpService {
  constructor(
    @InjectModel(Otp.name) private otpModel: Model<OtpDocument>,
    private mailService: MailService,
  ) {}

  // Generate 6-digit code and send email
  async generateOtp(email: string) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes validity

    // Save OTP to DB
    await this.otpModel.findOneAndUpdate(
      { email },
      { code, email, expiresAt, isUsed: false },
      { upsert: true, new: true },
    );

    // Send OTP email
    await this.mailService.sendOtpEmail(email, code);

    return { message: 'OTP sent to email' };
  }

  // Verify the OTP code
  async verifyOtp(email: string, code: string) {
    const otpRecord = await this.otpModel.findOne({ email, code, isUsed: false });

    if (!otpRecord) {
      throw new BadRequestException('Invalid OTP code');
    }

    if (otpRecord.expiresAt < new Date()) {
      throw new BadRequestException('OTP expired');
    }

    otpRecord.isUsed = true;
    await otpRecord.save();

    return { message: 'OTP verified successfully' };
  }
}