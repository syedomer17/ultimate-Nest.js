import { IsEmail, IsString, Matches, MinLength } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class SignupDto {
  @ApiProperty({
    description: 'Full name of the user',
    example: 'John Doe',
  })
  @IsString()
  name: string;

  @ApiProperty({
    description: 'Email address of the user',
    example: 'john@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Password with at least 6 characters and one number',
    example: 'password123',
  })
  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9]).+$/, {
    message: 'Password must contain at least one number',
  })
  password: string;
}
