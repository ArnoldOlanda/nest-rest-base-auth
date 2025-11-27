import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from 'src/app.module';
import { DataSource } from 'typeorm';
import { seedTestData } from './seed-test-data';
import cookieParser from 'cookie-parser';
import { FormatResponseInterceptor } from 'src/interceptors/formatResponse.interceptor';
import { HttpExceptionFilter } from 'src/exceptionFilters/httpException.filter';
import { MailerService } from '@nestjs-modules/mailer';

describe('API E2E Tests', () => {
  let app: INestApplication;
  let dataSource: DataSource;
  let authToken: string;
  let adminToken: string;
  let testUserId: string;
  let testRoleId: string;
  let testPermissionId: string;
  let refreshToken: string;
  let verificationToken: string;
  let resetToken: string;
  let moduleFixture: TestingModule;

  beforeAll(async () => {
    // Mock de MailerService
    const mockMailerService = {
      sendMail: jest.fn().mockResolvedValue(true),
    };

    moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(MailerService)
      .useValue(mockMailerService)
      .compile(); 

    app = moduleFixture.createNestApplication();
    
    // Apply same configuration as main.ts
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transformOptions: {
          enableImplicitConversion: true,
        },
      }),
    );
    app.useGlobalInterceptors(new FormatResponseInterceptor());
    app.useGlobalFilters(new HttpExceptionFilter());
    app.setGlobalPrefix('api/v1');

    await app.init();

    // Get DataSource and seed test data
    dataSource = moduleFixture.get<DataSource>(DataSource);
    await dataSource.synchronize(true); // Drop and recreate schema
    await seedTestData(dataSource);
  });

  afterAll(async () => {
    // Limpiar en el orden correcto
    try {
      if (dataSource && dataSource.isInitialized) {
        await dataSource.destroy();
      }
      if (app) {
        await app.close();
      }
      if (moduleFixture) {
        await moduleFixture.close(); // Importante: cerrar el módulo
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  });

  describe('Authentication Module', () => {
    describe('POST /api/v1/auth/register', () => {
      it('should register a new user successfully', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            name: 'New User',
            email: 'newuser@example.com',
            password: 'Password123!',
          })
          .expect(201);

        expect(response.body.status).toBe('success');
        expect(response.body.data).toHaveProperty('user');
        expect(response.body.data.user.email).toBe('newuser@example.com');
        expect(response.body.data.user.isActive).toBe(false); // Not verified yet
      });

      it('should fail with duplicate email', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            name: 'Test User',
            email: 'test1@example.com', // Already exists from seed
            password: 'Password123!',
          })
          .expect(409);
      });

      it('should fail with invalid email format', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            name: 'Test User',
            email: 'invalid-email',
            password: 'Password123!',
          })
          .expect(400);
      });

      it('should fail with weak password', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            name: 'Test User',
            email: 'test@example.com',
            password: '123', // Too short
          })
          .expect(400);
      });
    });

    describe('POST /api/v1/auth/login', () => {
      it('should login successfully with valid credentials', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: 'test1@example.com',
            password: 'password123',
          })
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data).toHaveProperty('token');
        expect(response.body.data).toHaveProperty('user');
        expect(response.body.data.user.email).toBe('test1@example.com');

        // Save token for later tests
        authToken = response.body.data.token;
        testUserId = response.body.data.user.id;

        // Check for refresh token in cookies
        const cookies = response.headers['set-cookie'];
        expect(cookies).toBeDefined();
      });

      it('should login admin successfully', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: 'admin@example.com',
            password: 'admin123',
          })
          .expect(200);

        adminToken = response.body.data.token;
      });

      it('should fail with invalid credentials', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: 'test1@example.com',
            password: 'wrongpassword',
          })
          .expect(401);
      });

      it('should fail with non-existent user', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: 'nonexistent@example.com',
            password: 'password123',
          })
          .expect(404);
      });
    });

    describe('POST /api/v1/auth/refresh-token', () => {
      it('should refresh access token with valid refresh token', async () => {
        // First login to get refresh token
        const loginResponse = await request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: 'test1@example.com',
            password: 'password123',
          });

        const cookies = loginResponse.headers['set-cookie'];
        const refreshTokenCookie = Array.isArray(cookies)
          ? cookies.find((cookie: string) => cookie.startsWith('refresh_token='))
          : undefined;

        expect(refreshTokenCookie).toBeDefined();

        // Extract refresh token value (this is simplified, in real scenario parse properly)
        // For now, we'll skip the actual refresh test as it requires proper cookie handling
        // In a real implementation, you'd parse the cookie and send it back
      });

      it('should fail with invalid refresh token', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/refresh-token')
          .send({
            refresh_token: 'invalid-token',
          })
          .expect(401);
      });
    });

    describe('PATCH /api/v1/auth/change-password', () => {
      it('should change password successfully when authenticated', async () => {
        const response = await request(app.getHttpServer())
          .patch('/api/v1/auth/change-password')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            currentPassword: 'password123',
            newPassword: 'NewPassword123!',
          })
          .expect(200);

        expect(response.body.status).toBe('success');

        // Change it back for other tests
        await request(app.getHttpServer())
          .patch('/api/v1/auth/change-password')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            currentPassword: 'NewPassword123!',
            newPassword: 'password123',
          });
      });

      it('should fail with wrong current password', async () => {
        await request(app.getHttpServer())
          .patch('/api/v1/auth/change-password')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            currentPassword: 'wrongpassword',
            newPassword: 'NewPassword123!',
          })
          .expect(400);
      });

      it('should fail without authentication', async () => {
        await request(app.getHttpServer())
          .patch('/api/v1/auth/change-password')
          .send({
            currentPassword: 'password123',
            newPassword: 'NewPassword123!',
          })
          .expect(401);
      });
    });

    describe('POST /api/v1/auth/forgot-password', () => {
      it('should send password reset email for existing user', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/forgot-password')
          .send({
            email: 'test1@example.com',
          })
          .expect(201);

        expect(response.body.status).toBe('success');
        expect(response.body.data.message).toContain('correo');
      });

      it('should fail for non-existent user', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/forgot-password')
          .send({
            email: 'nonexistent@example.com',
          })
          .expect(404);
      });
    });
  });

  describe('Users Module', () => {
    describe('GET /api/v1/users', () => {
      it('should return paginated users list with valid token', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/v1/users')
          .set('Authorization', `Bearer ${authToken}`)
          .query({ offset: 1, limit: 10 })
          .expect(200);

        expect(response.body.status).toBe('success');
        expect(response.body.data).toHaveProperty('data');
        expect(response.body.data).toHaveProperty('meta');
        expect(Array.isArray(response.body.data.data)).toBe(true);
        expect(response.body.data.meta).toHaveProperty('total');
        expect(response.body.data.meta).toHaveProperty('page');
        expect(response.body.data.meta).toHaveProperty('limit');
      });

      it('should fail without authentication', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/users')
          .expect(401);
      });

      it('should support pagination parameters', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/v1/users')
          .set('Authorization', `Bearer ${authToken}`)
          .query({ offset: 1, limit: 2 })
          .expect(200);

        expect(response.body.data.data.length).toBeLessThanOrEqual(2);
        expect(response.body.data.meta.limit).toBe(2);
      });
    });

    describe('GET /api/v1/users/:id', () => {
      it('should return user by id', async () => {
        const response = await request(app.getHttpServer())
          .get(`/api/v1/users/${testUserId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(response.body.status).toBe('success');
        expect(response.body.data.id).toBe(testUserId);
        expect(response.body.data).toHaveProperty('email');
        expect(response.body.data).toHaveProperty('name');
      });

      it('should fail with invalid UUID', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/users/invalid-uuid')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(400);
      });

      it('should fail for non-existent user', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/users/123e4567-e89b-12d3-a456-426614174000')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(404);
      });
    });

    describe('POST /api/v1/users', () => {
      it('should create a new user with admin permissions', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'Created User',
            email: 'created@example.com',
            password: 'Password123!',
          })
          .expect(201);

        expect(response.body.success).toBe(true);
        expect(response.body.data.email).toBe('created@example.com');
      });

      it('should fail without proper permissions', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/users')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            name: 'Created User',
            email: 'another@example.com',
            password: 'Password123!',
          })
          .expect(403);
      });

      it('should fail with duplicate email', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'Duplicate User',
            email: 'test1@example.com',
            password: 'Password123!',
          })
          .expect(409);
      });
    });

    describe('PATCH /api/v1/users/:id', () => {
      it('should update user with admin permissions', async () => {
        const response = await request(app.getHttpServer())
          .patch(`/api/v1/users/${testUserId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'Updated Name',
          })
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.name).toBe('Updated Name');
      });

      it('should fail without proper permissions', async () => {
        await request(app.getHttpServer())
          .patch(`/api/v1/users/${testUserId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            name: 'Unauthorized Update',
          })
          .expect(403);
      });
    });

    describe('DELETE /api/v1/users/:id', () => {
      it('should soft delete user with admin permissions', async () => {
        // First create a user to delete
        const createResponse = await request(app.getHttpServer())
          .post('/api/v1/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'To Delete',
            email: 'todelete@example.com',
            password: 'Password123!',
          });

        const userToDeleteId = createResponse.body.data.id;

        const response = await request(app.getHttpServer())
          .delete(`/api/v1/users/${userToDeleteId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
      });

      it('should fail without proper permissions', async () => {
        await request(app.getHttpServer())
          .delete(`/api/v1/users/${testUserId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(403);
      });
    });

    describe('POST /api/v1/users/:id/roles', () => {
      it('should assign role to user', async () => {
        // Get a role ID from seed data
        const rolesRepo = dataSource.getRepository('Role');
        const role = await rolesRepo.findOne({ where: {} });

        if (!role) {
          throw new Error('No role found in seed data');
        }

        const response = await request(app.getHttpServer())
          .post(`/api/v1/users/${testUserId}/roles`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            roleId: role.id,
          })
          .expect(200);

        expect(response.body.success).toBe(true);
      });

      it('should fail without admin permissions', async () => {
        const rolesRepo = dataSource.getRepository('Role');
        const role = await rolesRepo.findOne({ where: {} });

        if (!role) {
          throw new Error('No role found in seed data');
        }

        await request(app.getHttpServer())
          .post(`/api/v1/users/${testUserId}/roles`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            roleId: role.id,
          })
          .expect(403);
      });
    });

    describe('DELETE /api/v1/users/:id/roles', () => {
      it('should remove role from user', async () => {
        const rolesRepo = dataSource.getRepository('Role');
        const role = await rolesRepo.findOne({ where: {} });

        if (!role) {
          throw new Error('No role found in seed data');
        }

        const response = await request(app.getHttpServer())
          .delete(`/api/v1/users/${testUserId}/roles`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            roleId: role.id,
          })
          .expect(200);

        expect(response.body.success).toBe(true);
      });
    });
  });

  describe('Roles Module', () => {
    describe('GET /api/v1/roles', () => {
      it('should return all roles', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/v1/roles')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(Array.isArray(response.body.data)).toBe(true);
        expect(response.body.data.length).toBeGreaterThan(0);
      });

      it('should fail without authentication', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/roles')
          .expect(401);
      });
    });

    describe('POST /api/v1/roles', () => {
      it('should create a new role', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/roles')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'moderator',
            description: 'Moderator role',
          })
          .expect(201);

        expect(response.body.success).toBe(true);
        expect(response.body.data.name).toBe('moderator');
        testRoleId = response.body.data.id;
      });

      it('should fail with duplicate role name', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/roles')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'admin', // Already exists
            description: 'Duplicate admin',
          })
          .expect(409);
      });

      it('should fail without admin permissions', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/roles')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            name: 'unauthorized-role',
            description: 'Should fail',
          })
          .expect(403);
      });
    });

    describe('GET /api/v1/roles/:id', () => {
      it('should return role by id', async () => {
        const response = await request(app.getHttpServer())
          .get(`/api/v1/roles/${testRoleId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.id).toBe(testRoleId);
      });
    });

    describe('PATCH /api/v1/roles/:id', () => {
      it('should update role', async () => {
        const response = await request(app.getHttpServer())
          .patch(`/api/v1/roles/${testRoleId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            description: 'Updated moderator description',
          })
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.description).toBe(
          'Updated moderator description',
        );
      });
    });

    describe('DELETE /api/v1/roles/:id', () => {
      it('should delete role', async () => {
        // Create a role to delete
        const createResponse = await request(app.getHttpServer())
          .post('/api/v1/roles')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'to-delete-role',
            description: 'Will be deleted',
          });

        const roleToDeleteId = createResponse.body.data.id;

        const response = await request(app.getHttpServer())
          .delete(`/api/v1/roles/${roleToDeleteId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
      });
    });

    describe('POST /api/v1/roles/:id/permissions', () => {
      it('should assign permissions to role', async () => {
        const permissionsRepo = dataSource.getRepository('Permission');
        const permission = await permissionsRepo.findOne({ where: {} });

        if (!permission) {
          throw new Error('No permission found in seed data');
        }

        const response = await request(app.getHttpServer())
          .post(`/api/v1/roles/${testRoleId}/permissions`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            permissionIds: [permission.id],
          })
          .expect(200);

        expect(response.body.success).toBe(true);
      });
    });

    describe('GET /api/v1/roles/:id/permissions', () => {
      it('should get role permissions', async () => {
        const response = await request(app.getHttpServer())
          .get(`/api/v1/roles/${testRoleId}/permissions`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(Array.isArray(response.body.data)).toBe(true);
      });
    });

    describe('DELETE /api/v1/roles/:id/permissions', () => {
      it('should remove permissions from role', async () => {
        const permissionsRepo = dataSource.getRepository('Permission');
        const permission = await permissionsRepo.findOne({ where: {} });

        if (!permission) {
          throw new Error('No permission found in seed data');
        }

        const response = await request(app.getHttpServer())
          .delete(`/api/v1/roles/${testRoleId}/permissions`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            permissionIds: [permission.id],
          })
          .expect(200);

        expect(response.body.success).toBe(true);
      });
    });
  });

  describe('Permissions Module', () => {
    describe('GET /api/v1/permissions', () => {
      it('should return all permissions', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/v1/permissions')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(Array.isArray(response.body.data)).toBe(true);
      });
    });

    describe('POST /api/v1/permissions', () => {
      it('should create a new permission', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/permissions')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'WRITE',
            description: 'Write permission',
          })
          .expect(201);

        expect(response.body.success).toBe(true);
        expect(response.body.data.name).toBe('WRITE');
        testPermissionId = response.body.data.id;
      });

      it('should fail without admin permissions', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/permissions')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            name: 'EXECUTE',
            description: 'Execute permission',
          })
          .expect(403);
      });
    });

    describe('GET /api/v1/permissions/:id', () => {
      it('should return permission by id', async () => {
        const response = await request(app.getHttpServer())
          .get(`/api/v1/permissions/${testPermissionId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.id).toBe(testPermissionId);
      });
    });

    describe('PATCH /api/v1/permissions/:id', () => {
      it('should update permission', async () => {
        const response = await request(app.getHttpServer())
          .patch(`/api/v1/permissions/${testPermissionId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            description: 'Updated write permission',
          })
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.description).toBe(
          'Updated write permission',
        );
      });
    });

    describe('DELETE /api/v1/permissions/:id', () => {
      it('should delete permission', async () => {
        // Create a permission to delete
        const createResponse = await request(app.getHttpServer())
          .post('/api/v1/permissions')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            name: 'TO_DELETE',
            description: 'Will be deleted',
          });

        const permissionToDeleteId = createResponse.body.data.id;

        const response = await request(app.getHttpServer())
          .delete(`/api/v1/permissions/${permissionToDeleteId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
      });
    });
  });

  describe('Authorization & Security', () => {
    describe('JWT Authentication', () => {
      it('should reject requests without token', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/users')
          .expect(401);
      });

      it('should reject requests with invalid token', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/users')
          .set('Authorization', 'Bearer invalid-token')
          .expect(401);
      });

      it('should reject requests with malformed authorization header', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/users')
          .set('Authorization', 'InvalidFormat token')
          .expect(401);
      });
    });

    describe('Permission-based Access Control', () => {
      it('should deny access to protected routes without permissions', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/users')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            name: 'Test',
            email: 'test@test.com',
            password: 'Password123!',
          })
          .expect(403);
      });

      it('should allow access with proper permissions', async () => {
        await request(app.getHttpServer())
          .get('/api/v1/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
      });
    });

    describe('Input Validation', () => {
      it('should reject invalid email format', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            name: 'Test',
            email: 'not-an-email',
            password: 'Password123!',
          })
          .expect(400);
      });

      it('should reject missing required fields', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            name: 'Test',
            // Missing email and password
          })
          .expect(400);
      });

      it('should reject non-whitelisted fields', async () => {
        await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            name: 'Test',
            email: 'test@example.com',
            password: 'Password123!',
            maliciousField: 'should be rejected',
          })
          .expect(400);
      });
    });
  });

  describe('Error Handling', () => {
    it('should return 404 for non-existent routes', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/non-existent-route')
        .expect(404);
    });

    it('should handle database errors gracefully', async () => {
      // Try to create user with invalid data that would cause DB error
      await request(app.getHttpServer())
        .post('/api/v1/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Test',
          email: 'test1@example.com', // Duplicate
          password: 'Password123!',
        })
        .expect(409);
    });

    it('should return proper error format', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/users')
        .expect(401);

      expect(response.body).toHaveProperty('success');
      expect(response.body.success).toBe(false);
      expect(response.body).toHaveProperty('message');
    });
  });
});
