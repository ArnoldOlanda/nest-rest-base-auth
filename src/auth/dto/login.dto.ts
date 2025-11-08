import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";


export class LoginDto {
    @IsNotEmpty()
    @IsEmail()
    @ApiProperty({
        description: 'User email address',
        type: 'string',
        example: 'example@gmail.com'
    })
    email: string;

    @IsNotEmpty()
    @IsString()
    @MinLength(6)
    @ApiProperty({
        description: 'User password',
        type: 'string',
        minimum: 6,
        example: 'password123'
    })
    password: string;
}