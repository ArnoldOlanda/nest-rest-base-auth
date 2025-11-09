import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, MinLength } from "class-validator";

export class RegisterDto {
    @IsNotEmpty()
    @IsString()
    @ApiProperty({ example: 'John Doe', description: 'Nombre completo del usuario' })
    name: string;

    @IsNotEmpty()
    @IsString()
    @ApiProperty({ example: 'example@gmail.com', description: 'Correo electrónico del usuario' })
    email: string;

    @IsNotEmpty()
    @IsString()
    @MinLength(6)
    @ApiProperty({ example: 'strongPassword123', description: 'Contraseña del usuario' })
    password: string;
}