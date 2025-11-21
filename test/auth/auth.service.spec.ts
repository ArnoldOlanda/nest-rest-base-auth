import { Test, TestingModule } from "@nestjs/testing";
import { DataSource } from "typeorm";
import { TypeOrmModule } from "@nestjs/typeorm";
import { AuthService } from "src/auth/auth.service";
import { dataSource } from "src/config/dataSource";
import { User } from "src/users/entities/user.entity";
import { Role } from "src/auth/entities/role.entity";
import { Permission } from "src/auth/entities/permission.entity";
import { PasswordResetToken } from "src/auth/entities/passwordResetToken.entity";
import { EmailVerification } from "src/auth/entities/emailVerification.entity";
import { seedTestData } from "../seed-test-data";
import { Response } from "express";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { MailerService } from "@nestjs-modules/mailer";
import { EmailVerificationService } from "src/auth/emailVerification.service";
import { getQueueToken } from "@nestjs/bullmq";
import { SocialProviderUser } from "src/auth/interfaces";
import { SocialProvider } from "src/auth/enums/socialProvider.enum";

describe('Auth service unit test', () => {
    let service: AuthService;
    let dataSourceTesting: DataSource;
    let module: TestingModule;
    let mockResponse: Partial<Response>;

    beforeAll(async () => {
        // Mock de la cola de emails
        const mockEmailQueue = {
            add: jest.fn(),
        };

        // Mock de EmailVerificationService
        const mockEmailVerificationService = {
            create: jest.fn(() => Promise.resolve()),
            verifyToken: jest.fn(),
        };

        // Mock de JwtService
        const mockJwtService = {
            sign: jest.fn(() => 'mock-jwt-token'),
            signAsync: jest.fn(() => Promise.resolve('mock-jwt-token')),
            verify: jest.fn(),
            verifyAsync: jest.fn(() => Promise.resolve({ id: 'test-id' })),
        };

        // Mock de ConfigService
        const mockConfigService = {
            get: jest.fn((key: string) => {
                const config = {
                    JWT_SECRET: 'test-secret',
                    JWT_REFRESH_SECRET: 'test-refresh-secret',
                };
                return config[key];
            }),
        };

        // Mock de MailerService
        const mockMailerService = {
            sendMail: jest.fn(),
        };

        module = await Test.createTestingModule({
            imports: [
                TypeOrmModule.forRoot(dataSource),
                TypeOrmModule.forFeature([User, Role, Permission, PasswordResetToken, EmailVerification]),
            ],
            providers: [
                AuthService,
                {
                    provide: getQueueToken('email'),
                    useValue: mockEmailQueue,
                },
                {
                    provide: EmailVerificationService,
                    useValue: mockEmailVerificationService,
                },
                {
                    provide: JwtService,
                    useValue: mockJwtService,
                },
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: MailerService,
                    useValue: mockMailerService,
                },
            ],
        }).compile();

        service = module.get<AuthService>(AuthService);
        dataSourceTesting = module.get<DataSource>(DataSource);

        // Limpiar las tablas antes de poblar datos
        await dataSourceTesting.synchronize(true);
        
        await seedTestData(dataSourceTesting);
    });

    beforeEach(() => {
        mockResponse = {
            cookie: jest.fn().mockReturnThis(),
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
        };
    });

    afterAll(async () => {
        await dataSourceTesting.destroy();
        await module.close();
    });

    it('debería estar definido', () => {
        expect(service).toBeDefined();
    });

    it('debería poder validar usuario con credenciales correctas', async () => {
        const email = 'test1@example.com';
        const password = 'password123';

        await service.login(mockResponse as Response, { email, password });

        // Verificar que se llamó a cookie para establecer el refresh token
        expect(mockResponse.cookie).toHaveBeenCalledWith(
            'refresh_token',
            expect.any(String),
            expect.objectContaining({
                httpOnly: true,
                sameSite: 'none',
            })
        );

        // Verificar la estructura del JSON de respuesta
        expect(mockResponse.json).toHaveBeenCalledWith(
            expect.objectContaining({
                success: true,
                data: expect.objectContaining({
                    user: expect.any(User),
                    token: expect.any(String),
                }),
            })
        );
    });

    it('debería fallar con credenciales incorrectas', async () => {
        const email = 'test1@example.com';
        const password = 'wrong-password';

        await expect(
            service.login(mockResponse as Response, { email, password })
        ).rejects.toThrow();
    });

    it('debería fallar con usuario inexistente', async () => {
        const email = 'noexiste@example.com';
        const password = 'password123';

        await expect(
            service.login(mockResponse as Response, { email, password })
        ).rejects.toThrow('User not found');
    });

    it('Deberia registrar un nuevo usuario', async () => {
        const registerDto = {
            name: 'Nuevo Usuario',
            email: 'nuevo@gmail.com',
            password: 'nuevo123',
            avatar: 'avatar.png',
        };

        await service.register(registerDto);

        // Verificar que el usuario se haya creado en la base de datos
        const userRepository = dataSourceTesting.getRepository(User);
        const newUser = await userRepository.findOneBy({ email: registerDto.email });

        expect(newUser).toBeDefined();
        expect(newUser?.name).toBe(registerDto.name);
        expect(newUser?.email).toBe(registerDto.email);
    });

    it('Deberia registrar un nuevo usuario via social signIn', async () => {
        const socialDto:SocialProviderUser = {
            email: 'social@gmail.com',
            firstName: 'Social',
            lastName: 'User',
            social_provider: SocialProvider.GOOGLE,
        };

        const result = await service.socialProviderSignIn(socialDto, mockResponse as Response);

        expect(result).toBeDefined();
    });
})