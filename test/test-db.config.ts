import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Role } from 'src/auth/entities/role.entity';
import { Permission } from 'src/auth/entities/permission.entity';
import { EmailVerification } from 'src/auth/entities/emailVerification.entity';
import { PasswordResetToken } from 'src/auth/entities/passwordResetToken.entity';

export const testDbConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  host: 'localhost',
  port: 5434,
  username: 'test_user',
  password: 'test_password',
  database: 'test_db',
  entities: [User, Role, Permission, EmailVerification, PasswordResetToken],
  synchronize: true,
  dropSchema: true,
  logging: false,
};
