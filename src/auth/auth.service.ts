import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { LoginDto } from './dto/login.dto';
import { encryptText, verifyEncryptedText } from 'src/utils';
import { JwtPayload } from './interfaces';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import { PasswordResetToken } from './entities/passwordResetToken.entity';
import { EmailVerificationService } from './emailVerification.service';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(PasswordResetToken)
    private readonly passwordResetTokenRepository: Repository<PasswordResetToken>,
    private readonly emailVerificationService: EmailVerificationService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private readonly mailerService: MailerService,
  ) {}

  async login(res: Response, data: LoginDto) {
    try {
      const user = await this.userRepository.findOneBy({
        email: data.email,
      });
      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (!user.isActive) {
        throw new UnauthorizedException('User account is not active');
      }

      const checkPassword = verifyEncryptedText(data.password, user.password);
      if (!checkPassword) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const payload: JwtPayload = {
        id: user.id,
        name: user.name,
        email: user.email,
      };

      const token = this.generateToken(payload);
      const refreshToken = await this.generateRefreshToken(payload);

      // Set refresh token cookie http-only
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'prod',
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24 * 7,
      });

      return res.status(HttpStatus.OK).json({
        success: true,
        data: {
          user,
          token,
        },
      });
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error('Error during login', error);
      throw new InternalServerErrorException('Error during login');
    }
  }

  async register(registerDto: RegisterDto) {
    try {
      const { name, email, password } = registerDto;

      // Verificar si el usuario ya existe
      const existingUser = await this.userRepository.findOneBy({ email });
      if (existingUser) {
        throw new BadRequestException('El usuario ya está registrado');
      }

      // Crear usuario inactivo
      const encryptedPassword = encryptText(password);
      const user = this.userRepository.create({
        email,
        password: encryptedPassword,
        name,
      });
      await this.userRepository.save(user);

      // Generar token de activación
      const token = crypto.randomUUID();

      await this.emailVerificationService.create({ user, token });

      // Enviar correo de activación
      const activationUrl = this.generateActivationUrl(token);

      await this.sendEmailVerification(email, name, activationUrl);

      return {
        message:
          'Usuario registrado exitosamente. Revisa tu correo para activar tu cuenta.',
        user,
      };
    } catch (error) {
      this.logger.error('Error al registrar usuario', error);
      if(error instanceof HttpException){
        throw error;
      }
      throw new InternalServerErrorException('Error al registrar usuario');
    }
  }

  async activateAccount(token: string) {
    try {
      const emailVerification =
        await this.emailVerificationService.findAndValidateToken(token);

      if (!emailVerification) {
        throw new BadRequestException('Token de activación expirado o inválido');
      }

      emailVerification.user.isActive = true;

      await this.userRepository.save(emailVerification.user);

      await this.emailVerificationService.markAsUsed(emailVerification.id);

      return emailVerification.user;
    } catch (error) {
      if(error instanceof HttpException){
        throw error;
      }
      this.logger.error('Error al activar la cuenta', error);
      throw new InternalServerErrorException('Error al activar la cuenta');
    }
  }

  async resendEmailVerification(email: string) {
    try {
      const user = await this.userRepository.findOneBy({ email });
      
      if(!user){
        throw new NotFoundException(`User with email ${email} not found`);
      }

      if(user.isActive){
        throw new BadRequestException('User account is already active');
      }

      const token = crypto.randomUUID();
      
      await this.emailVerificationService.create({ user, token });

      const activationUrl = this.generateActivationUrl(token);

      await this.sendEmailVerification(user.email, user.name, activationUrl);

      return {
        message: 'Correo de verificación reenviado exitosamente',
      }

    }  catch (error) {
      if(error instanceof HttpException){
        throw error;
      }
      this.logger.error('Error al reenviar el correo de verificación', error);
      throw new InternalServerErrorException('Error al reenviar el correo de verificación');
    }
  }

  async refreshToken(refresh_token: string) {
    try {
      const refreshSecret = this.configService.get<string>(
        'REFRESH_TOKEN_SECRET',
      );
      const data = await this.jwtService.verifyAsync(refresh_token, {
        secret: refreshSecret,
      });
      this.logger.log('Refresh token verificado');

      const { exp, iat, ...payload } = data;
      const newAccessToken = await this.jwtService.signAsync(payload);

      return { token: newAccessToken };
    } catch (error) {
      this.logger.error('Error al verificar el token', error);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private generateRefreshToken(payload: any) {
    const refreshSecret = this.configService.get<string>(
      'REFRESH_TOKEN_SECRET',
    );
    return this.jwtService.signAsync(payload, {
      secret: refreshSecret,
      expiresIn: '7d',
    });
  }

  async forgotPassword(email: string) {
    try {
      const user = await this.userRepository.findOneBy({ email });
      if (!user) {
        throw new NotFoundException('The user does not exist');
      }

      // si es login con redes sociales no se puede cambiar la contraseña
      if (user.isSocialLogin) {
        throw new BadRequestException(
          'This user is connected with a social provider, this action is not allowed',
        );
      }

      // Invalidar tokens anteriores del usuario
      await this.passwordResetTokenRepository.update(
        { userId: user.id, isUsed: false },
        { isUsed: true },
      );

      // Generar nuevo token único (UUID)
      const tokenId = crypto.randomUUID();

      // Crear fecha de expiración (1 hora desde ahora)
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1);

      const resetToken = this.passwordResetTokenRepository.create({
        id: tokenId,
        userId: user.id,
        expiresAt,
        isUsed: false,
      });

      await this.passwordResetTokenRepository.save(resetToken);

      const url = `${this.configService.get<string>(
        'FRONTEND_URL',
      )}/auth/reset-password?token=${tokenId}`;

      await this.mailerService.sendMail({
        to: email,
        from: '"my app" <my-app@gmail.com>',
        subject: 'Recuperación de contraseña',
        template: 'forgotPassword',
        context: {
          email,
          url,
        },
      });

      return {
        message:
          'Se ha enviado un correo con las instrucciones para restablecer tu contraseña',
      };
    } catch (error) {
      this.logger.error('Error al enviar el correo de recuperación', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new InternalServerErrorException(
        'Error al enviar el correo de recuperación',
      );
    }
  }

  /**
   * Valida un token de reseteo de contraseña
   */
  validateResetToken(token: string) {
    try {
      return this.findTokenAndValidate(token);
    } catch (error) {
      this.logger.error(error);
      throw error;
    }
  }

  async resetPassword(token: string, password: string) {
    try {
      const resetToken = await this.findTokenAndValidate(token);

      // Marcar el token como usado
      resetToken.isUsed = true;
      await this.passwordResetTokenRepository.save(resetToken);

      // Actualizar la contraseña del usuario
      const user = resetToken.user;
      user.password = encryptText(password);
      await this.userRepository.update(user.id, user);

      return {
        message: 'Contraseña restablecida exitosamente',
        user,
      };
    } catch (error) {
      this.logger.error('Error al restablecer la contraseña', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new InternalServerErrorException(
        'Error al restablecer la contraseña',
      );
    }
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    // Verificar que no sea usuario de redes sociales
    if (user.isSocialLogin) {
      throw new BadRequestException(
        'Los usuarios de redes sociales no pueden cambiar la contraseña',
      );
    }

    // Verificar contraseña actual
    const isCurrentPasswordValid = verifyEncryptedText(
      currentPassword,
      user.password,
    );
    if (!isCurrentPasswordValid) {
      throw new BadRequestException('La contraseña actual es incorrecta');
    }

    // Verificar que la nueva contraseña sea diferente
    const isSamePassword = verifyEncryptedText(newPassword, user.password);
    if (isSamePassword) {
      throw new BadRequestException(
        'La nueva contraseña debe ser diferente a la actual',
      );
    }

    // Actualizar contraseña
    user.password = encryptText(newPassword);
    return this.userRepository.update(user.id, user);
  }

  private async findTokenAndValidate(token: string) {
    // Buscar el token en la base de datos
    const resetToken = await this.passwordResetTokenRepository.findOne({
      where: { id: token },
      relations: ['user'],
    });

    if (!resetToken) {
      throw new NotFoundException('Token de reseteo no encontrado');
    }

    // Verificar si el token es válido (no usado y no expirado)
    if (!resetToken.isValid()) {
      let message = 'El token de reseteo no es válido';

      if (resetToken.isUsed) {
        message = 'Este token ya ha sido utilizado';
      } else if (resetToken.isExpired()) {
        message = 'El token ha expirado. Por favor, solicita uno nuevo';
      }

      throw new BadRequestException(message);
    }

    return resetToken;
  }

  private generateToken(payload: { id: string }) {
    return this.jwtService.sign(payload);
  }

  private generateActivationUrl(token: string) {
    return `${this.configService.get<string>('FRONTEND_URL')}/auth/activate?token=${token}`;
  }

  private sendEmailVerification(email: string, name: string, activationUrl: string) {
    return this.mailerService.sendMail({
        to: email,
        from: '"My App" <no-reply@myapp.com>',
        subject: 'Activa tu cuenta',
        template: 'activation',
        context: {
          name,
          activationUrl,
        },
      });
  }
}
