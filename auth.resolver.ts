import {Resolver, Query, Mutation, Args, Context} from '@nestjs/graphql';
import {AuthService} from './auth.service';
import { LoginInput, RegisterInput, ResetPasswordInput } from './dto/auth.input';
import { Auth, ResetPasswordResponse, VerifyEmailResponse } from './models/auth.model';
import {Response, Request} from "express";

@Resolver('Auth')
export class AuthResolver {
    constructor(private readonly authService: AuthService) {
    }

    @Mutation(() => Auth, {name: 'login'})
    async login (@Args('loginInout') loginInput: LoginInput, @Context() context: {
        req: Request,
        res: Response
    }) {
        try {
            return await this.authService.login(loginInput, context.req.res);
        } catch (e) {
            return {
                error: {
                    message: e.message,
                    statusCode: 500,
                },
            };
        }
    }

    @Mutation(() => VerifyEmailResponse, {name: 'verifyEmail'})
    async verifyEmail(@Args('token') token: string) {
        try {
            return await this.authService.emailVerification(token);
        } catch (e) {
            return {
                error: {
                    message: e.message,
                    statusCode: 500,
                },
            };
        }
    }


    @Mutation(() => Auth, {name: 'register'})
    async register(@Args('registerInput') registerInput: RegisterInput, @Context() context: {
        req: Request,
        res: Response
    }) {
        try {
            const data = await this.authService.register(registerInput, context.res);
            return {
                data,
            };
        } catch (e) {
            return {
                error: {
                    message: e.message,
                    statusCode: e.statusCode,
                },
            };
        }
    }

    @Mutation(() => ResetPasswordResponse, {name: 'resetPassword'})
    async resetPassword(
        @Args('resetPasswordInput') resetPasswordInput: ResetPasswordInput,
    ) {
        try {
            return await this.authService.resetPassword(resetPasswordInput);
        } catch (e) {
            return {
                error: {
                    message: e.message,
                    statusCode: 500,
                },
            };
        }
    }

    @Query(() => Auth, {name: 'checkAuth'})
    async checkAuth(@Context() context: {
        req: Request,
        res: Response
    }) {
        try {
            return await this.authService.checkAuth(context.req, context.req.res);
        } catch (e) {
            return {
                error: {
                    message: e.message,
                    statusCode: 500,
                },
            };
        }
    }

    @Query(() => Auth, {name: 'refresh'})
    async refresh(@Context() context: {
        req: Request,
        res: Response
    }) {
        try {
            return await this.authService.refresh(context.req, context.req.res);
        } catch (e) {
            return {
                error: {
                    message: e.message,
                    statusCode: 500,
                },
            };
        }
    }

    @Query(() => Auth, {name: 'logout'})
    async logout(@Context() context: {
        req: Request,
        res: Response
    }) {
        try {
            return await this.authService.logout(context.req.res);
        } catch (e) {
            return {
                error: {
                    message: e.message,
                    statusCode: 500,
                },
            };
        }
    }

}
