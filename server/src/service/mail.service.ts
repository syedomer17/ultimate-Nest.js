import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    const user = this.configService.get<string>('EMAIL_USER') || "syedomerali2006@gmail.com";
    const pass = this.configService.get<string>('EMAIL_PASS') || "kxpnffcyrezabekc";

    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user,
        pass,
      },
    });

    // console.log('Email User:', user);
    // console.log('Email Pass:', pass);
  }

  async sendPasswordResetEmail(to: string, token: string): Promise<void> {
    const backendUrl = this.configService.get<string>('BACKEND_URL') || 'http://localhost:5000';
    const from = this.configService.get<string>('EMAIL_FROM') || 'Syed Omer Ali <syedomerali2006@gmail.com>';

    const resetLink = `${backendUrl}/reset-password?token=${token}`;

    const mailOptions = {
      from,
      to,
      subject: 'Password Reset Request',
      html: `
       <p>You requested a password reset.</p>
       <p>Click the link below to reset your password:</p>
       <a href="${resetLink}">Reset your password</a>
       <p>This link will expire in 3 hours.</p>
       <p>If you didn’t request this, please ignore this email.</p>
      `,
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendOtpEmail(to: string, code: string): Promise<void> {
    const from = this.configService.get<string>('EMAIL_FROM') || 'Syed Omer Ali <syedomerali2006@gmail.com>';

    const mailOptions = {
      from,
      to,
      subject: 'Email Verification Code',
      html: `<p>Your verification code is: <strong>${code}</strong></p>`,
    };

    await this.transporter.sendMail(mailOptions);
  }
  
}