import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schemas/user.schema';
import { Model, Types } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken, ResetTokenDocument } from './schemas/reset-token.schema';
import { MailService } from 'src/service/mail.service';
import { OtpService } from './otp.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<UserDocument>,
    private jwtService: JwtService,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private ResetTokenModel: Model<ResetTokenDocument>,
    private mailService: MailService,
    private otpService: OtpService,
  ) {}

  async signup(signupDataL: SignupDto) {
    const { email, password, name } = signupDataL;

    if (!name) {
      throw new BadRequestException('Name must be provided');
    }

    if (!email) {
      throw new BadRequestException('Email must be provided');
    }

    const existingUser = await this.UserModel.findOne({ email });
    if (existingUser) {
      throw new BadRequestException('Email already in use');
    }

    const existingName = await this.UserModel.findOne({ name });
    if (existingName) {
      throw new BadRequestException('Name already in use');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });

    await this.otpService.generateOtp(email);

    return {
      message: 'Signup successful! Please verify your email.',
      user: {
        id: newUser._id as string,
        name: newUser.name,
        email: newUser.email,
      },
    };
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;

    if (!email) {
      throw new BadRequestException('Email must be provided');
    }

    if (!password) {
      throw new BadRequestException('Password must be provided');
    }

    const checkUser = await this.UserModel.findOne({ email });

    if (!checkUser) {
      throw new BadRequestException('User not found');
    }

    const isPasswordValid = await bcrypt.compare(password, checkUser.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid password');
    }

    if (!checkUser.isEmailVerified) {
      throw new BadRequestException(
        'Email not verified, please verify your email first',
      );
    }

    const userId = checkUser._id as string;

    const tokens = await this.generateTokens(userId);

    return {
      message: 'Login successful',
      user: {
        id: userId,
        name: checkUser.name,
        email: checkUser.email,
      },
      ...tokens,
    };
  }

  async generateTokens(userId: string) {
    const accessToken = this.jwtService.sign(
      { userId, type: 'access' },
      { expiresIn: '7d' },
    );

    const refreshToken = uuidv4() + nanoid(16); // Unique refresh token

    await this.RefreshTokenModel.create({
      userId: new Types.ObjectId(userId),
      token: refreshToken,
      expiryDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return { accessToken, refreshToken };
  }

  async storeRefreshToken(token: string, userId: string) {
    const expiresDate = new Date();
    expiresDate.setDate(expiresDate.getDate() + 7);

    await this.RefreshTokenModel.updateOne(
      { userId },
      {
        $set: {
          token,
          userId: new Types.ObjectId(userId),
          expiresAt: expiresDate,
        },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );
  }

  // chanage password
  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (!oldPassword) {
      throw new BadRequestException('Old password  must be provided');
    }
    if (!newPassword) {
      throw new BadRequestException('New password must be provided');
    }
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Old password is incorrect');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    return {
      message: 'Password changed successfully',
      user: {
        id: user._id as string,
        name: user.name,
        email: user.email,
      },
    };
  }
  async forgotPassword(email: string) {
    const user = await this.UserModel.findOne({ email });

    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (user) {
      const expiresDate = new Date();
      expiresDate.setDate(expiresDate.getDate() + 7); // Token valid for 7 days

      const resetToken = nanoid(64); // Generate a unique reset token

      await this.ResetTokenModel.create({
        userId: user._id,
        token: resetToken,
        expiresAt: expiresDate,
      });
      await this.mailService.sendPasswordResetEmail(user.email, resetToken);
      return {
        message: 'Reset password email sent successfully',
        user: {
          id: user._id as string,
          name: user.name,
          email: user.email,
        },
      };
    }
  }

  async resetPassword(resetToken: string, newPassword: string) {
    const token = await this.ResetTokenModel.findByIdAndDelete({
      token: resetToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const userId = (token.userId as Types.ObjectId).toString();
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (!newPassword) {
      throw new BadRequestException('New password must be provided');
    }
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    return {
      message: 'Password reset successfully',
      user: {
        id: user._id as string,
        name: user.name,
        email: user.email,
      },
    };
  }
  async refreshToken(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOneAndDelete({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    const userId = token.userId.toString();
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    const newTokens = await this.generateTokens(userId);
    return {
      message: 'Tokens refreshed successfully',
      user: {
        id: user._id as string,
        name: user.name,
        email: user.email,
      },
      ...newTokens,
    };
  }

  async verifyEmail(email: string, otp: string) {
    await this.otpService.verifyOtp(email, otp);

    const updatedUser = await this.UserModel.findOneAndUpdate(
      { email },
      { $set: { isEmailVerified: true } },
      { new: true },
    );

    if (!updatedUser) {
      throw new NotFoundException('User not found');
    }

    return {
      message: 'Email verified successfully',
      user: {
        id: updatedUser._id as string,
        name: updatedUser.name,
        email: updatedUser.email,
        isEmailVerified: updatedUser.isEmailVerified,
      },
    };
  }
  async updateAvatar(email: string, avatarPath: string) {
    const user = await this.UserModel.findOneAndUpdate(
      { email },
      { avatar: avatarPath },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async getAvatar(email: string) {
    const user = await this.UserModel.findOne({ email });
    if (!user) throw new NotFoundException('User not found');
    return user.avatar;
  }
  async findUserById(userId: string) {
  const user = await this.UserModel.findById(userId);
  if (!user) {
    throw new NotFoundException('User not found');
  }
  return user;
}
}
