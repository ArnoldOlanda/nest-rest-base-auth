import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";

export class RegisterDto {
    @IsNotEmpty()
    @IsString()
    @ApiProperty({ example: 'John Doe', description: 'Nombre completo del usuario' })
    name: string;

    @IsNotEmpty()
    @IsEmail()
    @ApiProperty({ example: 'example@gmail.com', description: 'Correo electrónico del usuario' })
    email: string;

    @IsNotEmpty()
    @IsString()
    @MinLength(6)
    @ApiProperty({ example: 'strongPassword123', description: 'Contraseña del usuario' })
    password: string;
}