import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  ParseUUIDPipe,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PaginationDto } from './dto/pagination.dto';
import { Auth } from 'src/auth/decorators/auth.decorator';
import { Role } from 'src/auth/enums/validRoles.enum';
import { Permission } from 'src/auth/enums/permissions.enum';
import { ApiBearerAuth, ApiResponse } from '@nestjs/swagger';

@ApiBearerAuth()
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @Auth({permissions: [Permission.CREATE_USER]})
  @ApiResponse({ status: 201, description: 'Usuario creado exitosamente.' })
  @ApiResponse({ status: 400, description: 'Datos inválidos.' })
  @ApiResponse({ status: 409, description: 'Conflicto. El email ya existe.' })
  @ApiResponse({ status: 500, description: 'Error interno del servidor.' })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @Auth({permissions:[Permission.READ_USER]})
  @ApiResponse({ status: 200, description: 'Lista de usuarios obtenida correctamente.' })
  @ApiResponse({ status: 400, description: 'Parámetros de paginación inválidos.' })
  @ApiResponse({ status: 401, description: 'No autorizado.' })
  @ApiResponse({ status: 403, description: 'Prohibido.' })
  findAll(@Query() paginationDto: PaginationDto) {
    return this.usersService.findAll(paginationDto);
  }

  @Get(':id')
  @Auth({roles: [Role.ADMIN]})
  @ApiResponse({ status: 200, description: 'Usuario obtenido correctamente.' })
  @ApiResponse({ status: 400, description: 'ID inválido.' })
  @ApiResponse({ status: 401, description: 'No autorizado.' })
  @ApiResponse({ status: 403, description: 'Prohibido.' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado.' })
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Auth({roles: [Role.ADMIN]})
  @Patch(':id')
  @ApiResponse({ status: 200, description: 'Usuario actualizado correctamente.' })
  @ApiResponse({ status: 400, description: 'Datos inválidos.' })
  @ApiResponse({ status: 401, description: 'No autorizado.' })
  @ApiResponse({ status: 403, description: 'Prohibido.' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado.' })
  @ApiResponse({ status: 500, description: 'Error interno del servidor.' })
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @Auth({roles: [Role.ADMIN]})
  @Delete(':id')
  @ApiResponse({ status: 200, description: 'Usuario eliminado correctamente.' })
  @ApiResponse({ status: 400, description: 'ID inválido.' })
  @ApiResponse({ status: 401, description: 'No autorizado.' })
  @ApiResponse({ status: 403, description: 'Prohibido.' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado.' })
  @ApiResponse({ status: 500, description: 'Error interno del servidor.' })
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }

  @Auth({permissions: [Permission.UPDATE_USER]})
  @Post(':id/roles')
  @ApiResponse({ status: 200, description: 'Rol asignado correctamente al usuario.' })
  @ApiResponse({ status: 400, description: 'ID de usuario o rol inválido.' })
  @ApiResponse({ status: 401, description: 'No autorizado.' })
  @ApiResponse({ status: 403, description: 'Prohibido.' })
  @ApiResponse({ status: 404, description: 'Usuario o rol no encontrado.' })
  @ApiResponse({ status: 409, description: 'El usuario ya tiene el rol asignado.' })
  assignRoles(
    @Param('id') id: string,
    @Body('roleId', ParseUUIDPipe) role: string,
  ) {
    return this.usersService.assignRole(id, role);
  }
}
