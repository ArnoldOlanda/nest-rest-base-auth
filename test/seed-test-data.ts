import { DataSource } from 'typeorm';
import { Role } from 'src/auth/entities/role.entity';
import { Permission } from 'src/auth/entities/permission.entity';
import { User } from 'src/users/entities/user.entity';
import { encryptText } from 'src/utils';
import { v4 as uuid } from 'uuid';

export async function seedTestData(dataSource: DataSource) {
  const roleRepository = dataSource.getRepository(Role);
  const permissionRepository = dataSource.getRepository(Permission);
  const userRepository = dataSource.getRepository(User);

  // Crear roles
  const userRole = roleRepository.create({
    name: 'user',
    description: 'Usuario regular',
  });
  
  const adminRole = roleRepository.create({
    name: 'admin',
    description: 'Administrador',
  });

  await roleRepository.save([userRole, adminRole]);

  // Crear permisos (opcional)
  const readPermission = permissionRepository.create({
    name: 'READ',
    description: 'Permiso de lectura',
  });

  await permissionRepository.save([readPermission]);

  // Crear usuarios de prueba
  const testUser1 = userRepository.create({
    name: 'Test User 1',
    email: 'test1@example.com',
    password: encryptText('password123'),
    avatar: 'avatar1.png',
    isActive: true,
    roles: [userRole],
  });

  const testUser2 = userRepository.create({
    name: 'Test User 2',
    email: 'test2@example.com',
    password: encryptText('password123'),
    avatar: 'avatar2.png',
    isActive: true,
    roles: [userRole],
  });

  const adminUser = userRepository.create({
    name: 'Admin User',
    email: 'admin@example.com',
    password: encryptText('admin123'),
    avatar: 'admin.png',
    isActive: true,
    roles: [adminRole],
  });

  await userRepository.save([testUser1, testUser2, adminUser]);

  return {
    users: [testUser1, testUser2, adminUser],
    roles: [userRole, adminRole],
    permissions: [readPermission],
  };
}
