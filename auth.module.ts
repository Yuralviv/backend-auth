import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import {PrismaService} from "../prisma.service";
import {UsersService} from "../users/users.service";
import { JwtService } from '@nestjs/jwt';
import { TokensService } from '../tokens/tokens.service';
import { MailModule } from '../mail/mail.module';
import { MailService } from '../mail/mail.service';
import { ConfigService } from '@nestjs/config';
@Module({
  providers: [AuthResolver, AuthService, PrismaService, UsersService, JwtService, TokensService, MailModule, MailService, ConfigService],
})
export class AuthModule {}
