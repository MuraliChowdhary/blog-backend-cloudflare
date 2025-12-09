import { ZodError, ZodTypeAny } from 'zod';
import type { Context, Next } from 'hono';

interface SchemaParts {
  body?: ZodTypeAny;
  query?: ZodTypeAny;
  params?: ZodTypeAny;
}

export const validate = (schemas: SchemaParts) => {
  return async (c: Context, next: Next) => {
    try {
      const validatedData: Record<string, unknown> = {};

      // 1️⃣ Body
      if (schemas.body) {
        const body = await c.req.json().catch(() => ({}));
        validatedData.body = await schemas.body.parseAsync(body);
      }

      // 2️⃣ Query
      if (schemas.query) {
        const query = c.req.query();
        validatedData.query = await schemas.query.parseAsync(query);
      }

      // 3️⃣ Params
      if (schemas.params) {
        const params = c.req.param();
        validatedData.params = await schemas.params.parseAsync(params);
      }

      // Attach validated data to context
      c.set('validated', validatedData);

      await next();
    } catch (error) {
      if (error instanceof ZodError) {
        const formattedErrors = error.issues.map((err) => ({
          field: err.path.join('.') || 'body',
          message: err.message,
        }));

        return c.json(
          {
            status: 'error',
            message: 'Invalid request data. Please check the following fields.',
            errors: formattedErrors,
          },
          400
        );
      }

      console.error('[validate][ERROR]', error);
      return c.json(
        { status: 'error', message: (error as any)?.message || 'Internal server error' },
        500
      );
    }
  };
};
