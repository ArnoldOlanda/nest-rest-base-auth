import { Body, Controller, Get, InternalServerErrorException, Param, Patch, Post, Query, Request, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/changePassword.dto';
import { ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
import { Auth } from './decorators/auth.decorator';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { Throttle } from '@nestjs/throttler';
import { RegisterDto } from './dto/register.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Throttle({ default: { limit: 3, ttl: 60000, } }) // Limit to 3 requests per minute for login
  @Post('login')
  @ApiResponse({ status: 200, description: 'Login exitoso.' })
  @ApiResponse({ status: 401, description: 'Credenciales inválidas.' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado.' })
  @ApiResponse({ status: 500, description: 'Error interno del servidor.' })
  async login(@Body() body:LoginDto, @Res() res ) {
    return this.authService.login(res, body);
  }

  @Post('register')
  @ApiResponse({ status: 201, description: 'Registro exitoso. Se ha enviado un correo de activación.' })
  @ApiResponse({ status: 400, description: 'Datos inválidos.' })
  @ApiResponse({ status: 409, description: 'Conflicto. El email ya existe.' })
  @ApiResponse({ status: 500, description: 'Error interno del servidor.' })
  async register(
    @Body() body: RegisterDto
  ){
    return this.authService.register(body);
  }

  
  @Patch('activate')
  async activateAccount(@Query('token') token: string) {
    const result = await this.authService.activateAccount(token);
    return {
      message: 'Cuenta activada exitosamente',
      result,
    };
  }

  @Get('resend-email-verification')
  async resendEmailVerification(@Query('email') email: string) {
    return this.authService.resendEmailVerification(email);
  }

  @Post('refresh-token')
  @ApiResponse({ status: 200, description: 'Token actualizado exitosamente.' })
  @ApiResponse({ status: 401, description: 'Token de refresco inválido.' })
  async refreshToken(@Body('refresh_token') refreshToken: string) {
    return this.authService.refreshToken(refreshToken);
  }

  @Post('forgot-password')
  @ApiResponse({ status: 200, description: 'Correo de recuperación enviado.' })
  @ApiResponse({ status: 400, description: 'Usuario conectado con redes sociales.' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado.' })
  @ApiResponse({ status: 500, description: 'Error al enviar el correo.' })
  forgotPassword(@Body() body: ForgotPasswordDto) {
    const { email } = body;
    return this.authService.forgotPassword(email);
  }

  @Get('validate-reset-token/:token')
  @ApiResponse({ status: 200, description: 'Token válido.' })
  @ApiResponse({ status: 400, description: 'Token inválido, usado o expirado.' })
  @ApiResponse({ status: 404, description: 'Token no encontrado.' })
  validateResetToken(@Param('token') token: string) {
    return this.authService.validateResetToken(token);
  }

  @Post('reset-password')
  @ApiResponse({ status: 200, description: 'Contraseña restablecida exitosamente.' })
  @ApiResponse({ status: 400, description: 'Token inválido o contraseña inválida.' })
  @ApiResponse({ status: 404, description: 'Token no encontrado.' })
  @ApiResponse({ status: 500, description: 'Error al restablecer la contraseña.' })
  resetPassword(@Body() body: ResetPasswordDto) {
    const { token,  password } = body;
    return this.authService.resetPassword(token, password);
  }

  @ApiBearerAuth()
  @Auth()
  @Patch('change-password')
  @ApiResponse({ status: 200, description: 'Contraseña cambiada exitosamente.' })
  @ApiResponse({ status: 400, description: 'Contraseña actual incorrecta o nueva contraseña igual a la actual.' })
  @ApiResponse({ status: 401, description: 'No autorizado.' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado.' })
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Request() req: any,
  ) {
    return this.authService.changePassword(
      req.user.id,
      changePasswordDto.currentPassword,
      changePasswordDto.newPassword,
    );
  }
}
