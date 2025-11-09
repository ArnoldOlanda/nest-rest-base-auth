import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Role } from './entities/role.entity';
import { Permission } from './entities/permission.entity';
import { RoleService } from './role.service';
import { PermissionService } from './permission.service';
import { RoleController } from './role.controller';
import { PermissionController } from './permission.controller';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PasswordResetToken } from './entities/passwordResetToken.entity';
import { EmailVerification } from './entities/emailVerification.entity';
import { EmailVerificationService } from './emailVerification.service';

@Module({
    imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        TypeOrmModule.forFeature([User, Role, Permission, PasswordResetToken, EmailVerification]),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => ({
                secret:
                    configService.get<string>('JWT_SECRET') || 'defaultSecret',
                signOptions: { expiresIn: '8h' },
            }),
        }),
    ],
    controllers: [AuthController, RoleController, PermissionController],
    providers: [AuthService, JwtStrategy, RoleService, PermissionService, EmailVerificationService],
    exports: [JwtStrategy],
})
export class AuthModule {}
