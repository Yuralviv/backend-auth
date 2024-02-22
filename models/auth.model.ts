import {Field, ObjectType} from "@nestjs/graphql";
import {User} from "../../users/models/user.model";


@ObjectType()
export class Tokens {
    @Field(type => String)
    access_token: string;

    @Field(type => String)
    refresh_token: string;
}

@ObjectType()
export class Error {
    @Field(type => String)
    message: string;

    @Field(type => Number)
    statusCode: number;
}

@ObjectType()
export class AuthResponse {
    @Field(type => Tokens, {nullable: true})
    tokens: Tokens;

    @Field(type => User, {nullable: true})
    user: User;
}

@ObjectType()
export class TwoFactorResponse {
    @Field(type => Number)
    statusCode: number;

    @Field(type => String)
    message: string;
}

@ObjectType()
export class Success {
    @Field(type => Number)
    statusCode: number;

    @Field(type => String)
    message: string;
}

@ObjectType()
export class Auth {
    @Field(type => AuthResponse, {nullable: true})
    data?: AuthResponse;

    @Field(type => Error, {nullable: true})
    error?: Error;

    @Field(type => TwoFactorResponse, {nullable: true})
    twoFactor?: TwoFactorResponse;

    @Field(type => Success, {nullable: true})
    success?: Success;
}


@ObjectType()
export class VerifyEmailResponse {
    @Field(type => Success, {nullable: true})
    success?: Success;

    @Field(type => Error, {nullable: true})
    error?: Error;
}

@ObjectType()
export class LogoutResponse {
    @Field(type => Success, {nullable: true})
    success?: Success;

    @Field(type => Error, {nullable: true})
    error?: Error;
}

@ObjectType()
export class ResetPasswordResponse {
    @Field(type => Success, {nullable: true})
    success?: Success;

    @Field(type => Error, {nullable: true})
    error?: Error;
}

@ObjectType()
export class RefreshTokenResponse {
    @Field(type => Tokens, {nullable: true})
    tokens?: Tokens;

    @Field(type => Error, {nullable: true})
    error?: Error;
}