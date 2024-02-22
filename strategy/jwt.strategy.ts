import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt'
import { UsersService } from '../../users/users.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly userService: UsersService, private readonly configService: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: configService.get('JWT_SECRET'),
        });
    }

    async validate(payload: any) {
        const user = await this.userService.findByEmail(payload.email);

        if (!user) {
            throw new UnauthorizedException("Invalid token")
        }

        return user;
    }
}