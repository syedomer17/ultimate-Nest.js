import * as nodemailer from 'nodemailer';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailService.name);

  constructor(private configService: ConfigService) {
    const user = this.configService.get<string>('app.email.user');
    const pass = this.configService.get<string>('app.email.pass');

    if (!user || !pass) {
      this.logger.error('Email credentials missing in configuration.');
      throw new Error('EMAIL_USER or EMAIL_PASS is not set in config.');
    }

    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user, pass },
    });

    // Optional verification (for debugging/dev purposes)
    this.transporter.verify((err, success) => {
      if (err) {
        this.logger.error('Mail transporter verification failed', err);
      } else {
        this.logger.log('Mail transporter is ready to send emails.');
      }
    });
  }

  async sendPasswordResetEmail(to: string, token: string): Promise<void> {
    const backendUrl = this.configService.get<string>('app.backendUrl') ;
    const from = this.configService.get<string>('app.email.from') ;
    const resetLink = `${backendUrl}/reset-password?token=${token}`;

    const mailOptions = {
      from,
      to,
      subject: '🔐 Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <h2>Password Reset</h2>
          <p>You requested a password reset.</p>
          <p><a href="${resetLink}" style="color: #1a73e8;">Click here to reset your password</a></p>
          <p>This link will expire in 3 hours.</p>
          <p>If you didn’t request this, please ignore this email.</p>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Password reset email sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send password reset email to ${to}`, error);
    }
  }

  async sendOtpEmail(to: string, code: string): Promise<void> {
    const from = this.configService.get<string>('app.email.from');

    const mailOptions = {
      from,
      to,
      subject: '🔒 Email Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <h2>Email Verification</h2>
          <p>Your verification code is:</p>
          <h3 style="color: #1a73e8;">${code}</h3>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`OTP email sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send OTP email to ${to}`, error);
    }
  }
}
