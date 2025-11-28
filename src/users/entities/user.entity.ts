import { EmailVerification } from "../../auth/entities/emailVerification.entity";
import { Role } from "../../auth/entities/role.entity";
import { BeforeInsert, Column, CreateDateColumn, DeleteDateColumn, Entity, JoinTable, ManyToMany, OneToMany, PrimaryColumn, UpdateDateColumn } from "typeorm";
import {v4 as uuid} from 'uuid'

@Entity('users')
export class User {
    @PrimaryColumn({type: 'uuid'})
    id: string;

    @Column({type: 'varchar', length: 100})
    name: string;

    @Column({type: 'varchar', length: 100, unique: true})
    email: string;

    @Column({type: 'varchar', nullable: true})
    avatar: string | null;

    @Column({type: 'varchar'})
    password: string;

    @ManyToMany(() => Role)
    @JoinTable()
    roles: Role[];

    @OneToMany(()=>EmailVerification, emailVerification => emailVerification.user)
    emailVerifications: EmailVerification[];

    @Column({type: 'boolean', default: false})
    isActive: boolean;

    @Column({type: 'boolean', default: false})
    isSocialLogin: boolean;

    @Column({type: 'varchar', nullable: true})
    socialProvider: string;

    @DeleteDateColumn({type: 'timestamp', nullable: true})
    deletedAt: Date | null;

    @CreateDateColumn({type: 'timestamp'})
    createdAt: Date;

    @UpdateDateColumn({type: 'timestamp'})
    updatedAt: Date;

    @BeforeInsert()
    asignUuid(){
        this.id = uuid();
    }
}
