import { BadRequestException, Injectable } from '@nestjs/common';
import { LoginInput, RegisterInput, ResetPasswordInput } from './dto/auth.input';
import { PrismaService } from '../prisma.service';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { Role, User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import { TokensService } from '../tokens/tokens.service';
import { MailService } from '../mail/mail.service';
import { ConfigService } from '@nestjs/config';


@Injectable()
export class AuthService {
    constructor(private readonly prisma: PrismaService, private readonly userService: UsersService, private jwtService: JwtService, private readonly tokensService: TokensService, private  readonly mailService: MailService, private readonly configService: ConfigService) {
    }

    async register(input: RegisterInput, res: Response) {
        const existingUser = await this.userService.findByEmail(input.email);

        if (existingUser) {
            throw new BadRequestException('Email already exists');
        }

        const hashedPassword = await bcrypt.hash(input.password, 10);

        const user = await this.prisma.user.create({
            data: {
                email: input.email,
                password: hashedPassword,
                last_name: input.last_name,
                first_name: input.first_name,
            },
        });

        return await this.issueToken(user, res);
    }


    async login(input: LoginInput, res: Response) {
        const { email, password, code, isAdmin } = input;

        const user = await this.userService.findByEmail(email);


        if (!user) {
            throw new BadRequestException('Invalid credentials');
        }

        const passwordValid = await bcrypt.compare(password, user.password);

        if (!passwordValid) {
            throw new BadRequestException('Invalid credentials');
        }

        if (isAdmin && user.role !== Role.ADMIN) {
            throw new BadRequestException('Invalid credentials');
        }

        if (!user.emailVerified) {
            const verificationToken = await this.tokensService.generateVerificationToken(email);

            await this.mailService.sendUserConfirmation(user, verificationToken.token, isAdmin);

            return {
                success: {
                    statusCode: 200, message: 'Please verify your email address',
                },
            };
        }

        if (user.isTwoFactorEnabled && user.email) {
            if (code) {
                const twoFactorToken = await this.prisma.twoFactorToken.findFirst({
                    where: {
                        email,
                    },
                });


                if (!twoFactorToken) {
                    throw new BadRequestException('Invalid code!');
                }

                if (twoFactorToken.token !== code) {
                    throw new BadRequestException('Invalid code!');
                }

                const hasExpired = new Date(twoFactorToken.expires) < new Date();

                if (hasExpired) {
                    throw new BadRequestException('Invalid code!');
                }

                await this.prisma.twoFactorToken.delete({
                    where: {
                        id: twoFactorToken.id,
                    },
                });

                const existingConfirmation = await this.prisma.twoFactorConfirmation.findFirst({
                    where: {
                        userId: user.id,
                    },
                });

                if (existingConfirmation) {
                    await this.prisma.twoFactorConfirmation.delete({
                        where: {
                            id: existingConfirmation.id,
                        },
                    });
                }

                await this.prisma.twoFactorConfirmation.create({
                    data: {
                        userId: user.id,
                    },
                });

                return await this.issueToken(user, res);
            } else {
                const twoFactorToken = await this.tokensService.generateTwoFactorToken(email);

                await this.mailService.sendUserTwoFactorCode(user, twoFactorToken.token);

                return {
                    twoFactor: {
                        statusCode: 200, message: 'Please enter the code sent to your email',
                    },
                };
            }
        }

        return await this.issueToken(user, res);
    }

    async emailVerification(token: string) {
        const verificationToken = await this.prisma.verificationToken.findFirst({
            where: {
                token,
            },
        })

        if (!verificationToken) {
            throw new BadRequestException('Invalid token');
        }

        const hasExpired = new Date(verificationToken.expires) < new Date();

        if (hasExpired) {
            throw new BadRequestException('Invalid token');
        }

        const user = await this.userService.findByEmail(verificationToken.email);

        if (!user) {
            throw new BadRequestException('Invalid token');
        }

        await this.prisma.user.update({
            where: {
                id: user.id,
            },
            data: {
                emailVerified: true,
            },
        });

        await this.prisma.verificationToken.delete({
            where: {
                id: verificationToken.id,
            },
        });

        return {
            success: {
                statusCode: 200,
                message: 'Email verified successfully',
            },
        };
    }

    async issueToken(user: User, res: Response) {
        const payload = {
            id: user.id,
            email: user.email,
        };

        const access_token = await this.jwtService.signAsync(payload, {
            secret: process.env.JWT_SECRET,
            expiresIn: '1h',
        });

        const refresh_token = await this.jwtService.signAsync(payload, {
            secret: process.env.JWT_SECRET,
            expiresIn: '1d',
        });

        res.cookie('refresh_token', refresh_token);
        res.cookie('access_token', access_token);

        return {
            data: {
                tokens: {
                    access_token,
                    refresh_token,
                },
                user,
            },
        };
    }

    async logout(res: Response) {
        res.clearCookie('refresh_token');
        res.clearCookie('access_token');

        return {
            success: {
                statusCode: 200,
                message: 'Logged out successfully',
            },
        };
    }

    async refresh(req: Request, res: Response) {
        const {refresh_token} = req.cookies;

        const { email } = await this.jwtService.verifyAsync(refresh_token, {
            secret: this.configService.get("JWT_SECRET"),
        });

        const user = await this.userService.findByEmail(email);

        if (!user) {
            await this.logout(res)
            throw new BadRequestException('Invalid token');
        }

        return await this.issueToken(user, res);
    }

    async checkAuth (req: Request, res: Response) {

        const { access_token } = req.cookies;

        if (!access_token) {
            throw new BadRequestException('Invalid token');
        }

        const { email } = await this.jwtService.verifyAsync(access_token, {
            secret: this.configService.get("JWT_SECRET"),
        });

        const user = await this.userService.findByEmail(email);

        if (!user) {
            throw new BadRequestException('Invalid token');
        }

        return  await this.issueToken(user, res);
    }

    async resetPassword(input: ResetPasswordInput) {
        const { token, newPassword, email } = input;

        if(email) {
            const user = await this.userService.findByEmail(email);

            if (!user) {
                throw new BadRequestException('Invalid email');
            }

            const resetToken = await this.tokensService.generateResetPasswordToken(email);

            await this.mailService.sendUserPasswordReset(user, resetToken.token, );

            return {
                success: {
                    statusCode: 200,
                    message: 'Password reset email sent',
                },
            };
        }else if (token && newPassword) {
            const resetToken = await this.prisma.passwordResetToken.findFirst({
                where: {
                    token,
                },
            });

            if (!resetToken) {
                throw new BadRequestException('Invalid token');
            }

            const hasExpired = new Date(resetToken.expires) < new Date();

            if (hasExpired) {
                throw new BadRequestException('Invalid token');
            }

            const user = await this.userService.findByEmail(resetToken.email);

            if (!user) {
                throw new BadRequestException('Invalid token');
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            await this.prisma.user.update({
                where: {
                    id: user.id,
                },
                data: {
                    password: hashedPassword,
                },
            });

            await this.prisma.passwordResetToken.delete({
                where: {
                    id: resetToken.id,
                },
            });

            return {
                success: {
                    statusCode: 200,
                    message: 'Password reset successfully',
                },
            };
        }

    }
}
