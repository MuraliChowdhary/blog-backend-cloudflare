// utils/cors.ts
export function getCorsHeaders(origin = '*') {
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '600',
    };
}
export function handleOptions(origin = '*') {
    return new Response(null, {
        status: 204,
        headers: getCorsHeaders(origin),
    });
}
