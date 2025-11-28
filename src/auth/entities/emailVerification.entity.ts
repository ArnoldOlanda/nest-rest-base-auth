import { User } from "../../users/entities/user.entity";
import { BeforeInsert, Column, CreateDateColumn, Entity, ManyToOne, PrimaryColumn, UpdateDateColumn } from "typeorm";
import {v4 as uuid} from 'uuid'

@Entity('email_verifications')
export class EmailVerification {

    @PrimaryColumn({type: 'uuid'})
    id:string;

    @ManyToOne(() => User, user => user.emailVerifications)
    user: User;

    @Column({type: 'varchar'})
    tokenHash: string;

    @Column({type: 'timestamp'})
    expiresAt: Date;

    @Column({type: 'boolean', default: false})
    isUsed: boolean;

    @CreateDateColumn({type: 'timestamp'})
    createdAt: Date;

    @UpdateDateColumn({type: 'timestamp'})
    updatedAt: Date;

    @BeforeInsert()
    asignUuid(){
        this.id = uuid();
    }
}