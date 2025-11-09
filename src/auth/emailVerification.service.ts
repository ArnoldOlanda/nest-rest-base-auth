import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { EmailVerification } from './entities/emailVerification.entity';
import { Repository } from 'typeorm';
import { encryptText, verifyEncryptedText } from 'src/utils';

@Injectable()
export class EmailVerificationService {
    constructor(
        @InjectRepository(EmailVerification)
        private readonly emailVerificationRepository: Repository<EmailVerification>,
    ) {}

    /**
     * Crea un nuevo registro de verificación de email.
     * @param user - Usuario para el que se crea la verificación.
     * @param token - Token de verificación en texto plano (será hasheado).
     * @returns El registro de verificación creado.
     */
    async create({ user, token }: { user: User; token: string }) {
        const emailVerification = this.emailVerificationRepository.create({
            user,
            tokenHash: encryptText(token),
            // expiresAt: new Date(Date.now() + 60000), // 1 min for testing
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 horas
        });

        return this.emailVerificationRepository.save(emailVerification);
    }

    /**
     * Busca y valida un token de verificación de email.
     * Como el token está hasheado, busca todos los tokens no usados y no expirados,
     * luego valida el token proporcionado contra cada hash.
     * @param token - Token de activación en texto plano.
     * @returns La verificación de email si el token es válido, null en caso contrario.
     */
    async findAndValidateToken(token: string) {
        // Buscar todas las verificaciones no usadas y no expiradas
        const verifications = await this.emailVerificationRepository.find({
            where: { 
                isUsed: false,
            },
            relations: ['user'],
        });

        // Buscar la verificación que coincida con el token
        for (const verification of verifications) {
            // Verificar si el token no ha expirado
            if (new Date() > verification.expiresAt) {
                continue;
            }

            // Comparar el hash
            const isValid = verifyEncryptedText(token, verification.tokenHash);
            if (isValid) {
                return verification;
            }
        }

        return null;
    }

    /**
     * Marca un registro de verificación como usado.
     * @param id - ID del registro de verificación.
     * @returns El resultado de la actualización.
     */
    async markAsUsed(id: string) {
        return await this.emailVerificationRepository.update(id, {
            isUsed: true,
        });
    }
}
