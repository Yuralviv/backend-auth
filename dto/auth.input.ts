import { Field, InputType } from '@nestjs/graphql';


@InputType()
export class RegisterInput {
    @Field(type => String)
    email: string;

    @Field(type => String)
    password: string;

    @Field(type => String)
    first_name: string;

    @Field(type => String)
    last_name: string;
}


@InputType()
export class LoginInput {
    @Field(type => String)
    email: string;

    @Field(type => String)
    password: string;

    @Field(type => String , {nullable: true})
    code?: string;

    @Field(type => Boolean, {nullable: true})
    isAdmin: boolean;

    @Field(type => Boolean, {nullable: true})
    rememberMe: boolean;
}

@InputType()
export class ResetPasswordInput {
    @Field(type => String, {nullable: true})
    token: string;

    @Field(type => String, {nullable: true})
    newPassword: string;

    @Field(type => String, {nullable: true})
    email: string;
}

