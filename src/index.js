import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { blogRouter } from './routes/blog';
import { userRouters } from './routes/authRoutes';
const app = new Hono();
app.use('/api/*', cors({
    origin: [
        'https://blog-pnp.vercel.app',
        'https://blog.pickandpartner.com',
        'http://localhost:3000',
        'https://blog-newsletter-lemon.vercel.app',
        'https://blog.nextdevs.me/'
    ],
    allowHeaders: [
        'Content-Type', // This is essential for JSON requests
        'Authorization', // For JWT tokens
        'X-Custom-Header',
        'Upgrade-Insecure-Requests'
    ],
    allowMethods: ['POST', 'GET', 'OPTIONS', 'PUT', 'DELETE'],
    exposeHeaders: ['Content-Length', 'X-Kuma-Revision'],
    maxAge: 600,
    credentials: true,
}));
// OPTIONS handler (🔥 Required for preflight requests)
// app.options('*', (c) => {
//   const origin = c.req.header('Origin') ?? '*';
//   return handleOptions(origin);
// });
// Root route
app.get('/', (c) => {
    return c.json({
        message: 'NextDevs Blog API is running!',
        version: '1.0.0',
    });
});
// Routes
app.route('/api/v1/user', userRouters);
app.route('/api/v1/blog', blogRouter);
// Error handling
app.notFound((c) => {
    return c.json({ error: 'Route not found' }, 404);
});
app.onError((err, c) => {
    console.error('Unhandled error:', err);
    return c.json({ error: 'Internal server error' }, 500);
});
export default app;
