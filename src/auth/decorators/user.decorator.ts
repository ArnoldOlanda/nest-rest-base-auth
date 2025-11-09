import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const User = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    // Si el decorador se llama como @User('email') devuelve solo esa propiedad
    return data ? user?.[data] : user;
  },
);
