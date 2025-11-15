import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { UsersService } from 'src/users/users.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { testDbConfig } from '../test-db.config';
import { seedTestData } from '../seed-test-data';
import { User } from 'src/users/entities/user.entity';
import { Role } from 'src/auth/entities/role.entity';
import { Permission } from 'src/auth/entities/permission.entity';
import { EmailVerification } from 'src/auth/entities/emailVerification.entity';
import { PasswordResetToken } from 'src/auth/entities/passwordResetToken.entity';

describe('UsersService (con DB real)', () => {
  let service: UsersService;
  let dataSource: DataSource;
  let module: TestingModule;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot(testDbConfig),
        TypeOrmModule.forFeature([User, Role, Permission, EmailVerification, PasswordResetToken]),
      ],
      providers: [UsersService],
    }).compile();

    service = module.get<UsersService>(UsersService);
    dataSource = module.get<DataSource>(DataSource);

    // Poblar datos de prueba
    await seedTestData(dataSource);
  });

  afterAll(async () => {
    await dataSource.destroy();
    await module.close();
  });

  it('debería estar definido', () => {
    expect(service).toBeDefined();
  });

  it('findAll debe devolver usuarios de prueba', async () => {
    const result = await service.findAll({ limit: 10, offset: 0 });
    
    expect(result.users.length).toBeGreaterThan(0);
    expect(result.total).toBeGreaterThan(0);
    expect(result.users[0]).toHaveProperty('id');
    expect(result.users[0]).toHaveProperty('email');
  });

  it('create debe agregar un nuevo usuario', async () => {
    const userTest: CreateUserDto = {
      name: 'Nuevo Usuario',
      email: 'nuevo@example.com',
      password: 'password123',
      avatar: 'avatar.png',
    };

    const user = await service.create(userTest);

    expect(user).toHaveProperty('id');
    expect(user.name).toBe(userTest.name);
    expect(user.email).toBe(userTest.email);

    // Verificar que se guardó en la DB
    const found = await service.findOne(user.id);
    expect(found).toBeDefined();
    expect(found.id).toBe(user.id);
  });

  it('findOne debe encontrar un usuario existente', async () => {
    // Primero obtenemos un usuario de los datos de prueba
    const allUsers = await service.findAll({ limit: 1, offset: 0 });
    const existingUserId = allUsers.users[0].id;

    const found = await service.findOne(existingUserId);

    expect(found).toBeDefined();
    expect(found.id).toBe(existingUserId);
  });

  it('create debe fallar con email duplicado', async () => {
    const userTest: CreateUserDto = {
      name: 'Test Duplicado',
      email: 'test1@example.com', // Email que ya existe en los datos de prueba
      password: 'password123',
      avatar: 'avatar.png',
    };

    await expect(service.create(userTest)).rejects.toThrow();
  });

  it('update debe modificar un usuario', async () => {
    // Crear un usuario para actualizar
    const newUser = await service.create({
      name: 'Usuario para actualizar',
      email: 'actualizar@example.com',
      password: 'password123',
      avatar: 'avatar.png',
    });

    const updatedData = {
      name: 'Usuario Actualizado',
    };

    const updated = await service.update(newUser.id, updatedData);

    expect(updated.name).toBe(updatedData.name);
    expect(updated.email).toBe(newUser.email); // Email no cambió
  });

  it('remove debe eliminar un usuario (soft delete)', async () => {
    // Crear un usuario para eliminar
    const userToDelete = await service.create({
      name: 'Usuario a eliminar',
      email: 'eliminar@example.com',
      password: 'password123',
      avatar: 'avatar.png',
    });

    await service.remove(userToDelete.id);

    // Verificar que ya no se puede encontrar
    await expect(service.findOne(userToDelete.id)).rejects.toThrow();
  });
});
