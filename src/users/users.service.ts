import { ConflictException, Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PaginationDto } from './dto/pagination.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { encryptText } from 'src/utils';
import { Role } from 'src/auth/entities/role.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
  ) {}

  async create(createUserDto: CreateUserDto) {
    try {
      const { password, ...rest } = createUserDto;

      const encryptedPassword = encryptText(password);
      const user = this.userRepository.create({
        ...rest,
        password: encryptedPassword,
      });
      return await this.userRepository.save(user);
    } catch (error) {
      console.log(error.message);
      
      if (error.code === '23505') {
        throw new ConflictException('Email already exists');
      }
      throw new InternalServerErrorException({
        success: false,
        message: 'Error creating user',
      });
    }
  }

  async findAll(paginationDto: PaginationDto) {
    const { limit = 10, offset = 0 } = paginationDto;

    const [users, total] = await this.userRepository.findAndCount({
      relations: ['roles'],
      take: limit,
      skip: offset,
    });

    return {
      users,
      total,
      limit,
      offset,
      pages: Math.ceil(total / limit),
    };
  }

  async findOne(id: string) {
    const user = await this.userRepository.findOneBy({ id });
    
    if (!user) {
      throw new NotFoundException(`User with id ${id} not found`);
    }
    
    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    try {
      const user = await this.userRepository.preload({
        id,
        ...updateUserDto,
      });

      if (!user) {
        throw new NotFoundException(`User with id ${id} not found`);
      }

      return await this.userRepository.save(user);
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      if (error.code === '23505') {
        throw new ConflictException('Email already exists');
      }
      throw new InternalServerErrorException('Error updating user');
    }
  }

  async remove(id: string) {
    const user = await this.userRepository.findOne({ where: { id }, withDeleted: false });
    if(!user){
      throw new NotFoundException(`User with id ${id} not found`);
    }
    user.isActive = false;
    await this.userRepository.save(user);
    return this.userRepository.softDelete(id);
  }

  //Role assignment
  async assignRole(userId: string, roleId: string) {
    const user = await this.userRepository.findOne({ where: { id: userId }, relations: ['roles'] });
    if (!user) {
      throw new NotFoundException(`User with id ${userId} not found`);
    }

    const role = await this.roleRepository.findOneBy({ id: roleId });
    if (!role) {
      throw new NotFoundException(`Role with id ${roleId} not found`);
    }

    // Verificar si el usuario ya tiene el rol
    if (Array.isArray(user.roles) && user.roles.some(r => r.id === roleId)) {
      throw new ConflictException(`User already has the role "${role.name}"`);
    }

    user.roles = Array.isArray(user.roles) ? [...user.roles, role] : [role];
    await this.userRepository.save(user);

    return `Rol asignado correctamente.`;
  }
}
