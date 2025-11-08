import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsUrl, Length } from "class-validator";

export class CreateUserDto {

    @IsString()
    @IsNotEmpty()
    @ApiProperty({
        description: 'User full name',
        type: 'string',
        example: 'John Doe'
    })
    name: string;

    @IsEmail()
    @IsNotEmpty()
    @ApiProperty({
        description: 'User email address',
        type: 'string',
        example: 'example@gmail.com'
    })
    email: string;

    @IsString()
    @IsNotEmpty()
    @Length(6, 20)
    @ApiProperty({
        description: 'User password',
        type: 'string',
        minimum: 6,
        example: 'password123'
    })
    password: string;

    @IsOptional()
    @IsUrl()
    @ApiProperty({
        description: 'URL of the user avatar image',
        type: 'string',
        example: 'https://example.com/avatar.jpg',
        required: false,
    })
    avatar?: string;
}
