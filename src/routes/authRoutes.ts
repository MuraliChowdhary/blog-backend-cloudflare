import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client/edge';
import { withAccelerate } from '@prisma/extension-accelerate';
import { sign, verify } from 'hono/jwt';
import bcrypt from 'bcryptjs';

import {getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { validate } from '../utils/validate.middleware';
import { userSchema } from '../utils/zod.types';
// No longer importing PrismaClientKnownRequestError

type Binding = {
  DATABASE_URL: string;
  JWT_SECRET: string;
  NODE_ENV: 'development' | 'production';
  NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME: string;
  CLOUDINARY_API_KEY: string;
  CLOUDINARY_API_SECRET: string;
};

type Variables = {
  userId: string;
  userRole: 'ADMIN' | 'USER';
};

export const userRouters = new Hono<{ Bindings: Binding, Variables: Variables }>();


// --- User Authentication Routes ---

// Signup route with role assignment
// userRouters.post('/signup', async (c) => {
//   const prisma = new PrismaClient({
//     datasourceUrl: c.env.DATABASE_URL,
//   }).$extends(withAccelerate());

//   try {
//     const body = await c.req.json();

//     // Validation
//     if (!body.email || !body.password) {
//       return c.json({ error: 'Email and password are required' }, 400);
//     }

//     if (body.password.length < 6) {
//       return c.json({ error: 'Password must be at least 6 characters long' }, 400);
//     }

//     // Check if user already exists
//     const existingUser = await prisma.user.findFirst({
//       where: {
//         email: body.email,
//       },
//     });

//     if (existingUser) {
//       return c.json({ error: 'User already exists with this email' }, 409);
//     }

//     // Hash password
//     const hashedPassword = await bcrypt.hash(body.password, 12);

//     const user = await prisma.user.create({
//       data: {
//         name: body.name,
//         email: body.email,
//         password: hashedPassword,
//         role: body.role === 'ADMIN' ? 'ADMIN' : 'USER',
//         avatar: body.avatar,
//         bio: body.bio,
//       },
//       select: {
//         id: true,
//         email: true,
//         name: true,
//         role: true,
//         avatar: true,
//         bio: true,
//         createdAt: true,
//         postsCount: true,
//         receivedLikesCount: true,
//       }
//     });

//     // Generate JWT token
//     const token = await sign({
//       id: user.id,
//       email: user.email,
//       role: user.role
//     }, c.env.JWT_SECRET);

//     return c.json({
//       message: 'User created successfully',
//       jwt: token,
//       user
//     });
//   } catch (error: unknown) {
//     console.error('Signup error:', error);
//     if (error instanceof Error) {
//       if (error.name === 'JWTError' || error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
//         return c.json({ error: 'Invalid or expired token during signup token generation' }, 401);
//       }
//       // Check for Prisma error code 'P2002' using duck typing
//       // We check if the error object has a 'code' property and a 'meta' property
//       // This is less type-safe than `instanceof PrismaClientKnownRequestError` but works.
//       if (
//         (error as any).code === 'P2002' &&
//         (error as any).meta &&
//         typeof (error as any).meta.target === 'object' &&
//         Array.isArray((error as any).meta.target) &&
//         (error as any).meta.target.includes('email')
//       ) {
//         return c.json({ error: 'User already exists with this email' }, 409);
//       }
//       return c.json({ error: error.message }, 500);
//     }
//     return c.json({ error: 'Unknown error occurred' }, 500);
//   } finally {
//     await prisma.$disconnect();
//   }
// });

// // Signin route with enhanced response
// userRouters.post('/signin', async (c) => {
//   const prisma = new PrismaClient({
//     datasourceUrl: c.env.DATABASE_URL,
//   }).$extends(withAccelerate());

//   try {
//     const body = await c.req.json();

//     // Validation
//     if (!body.email || !body.password) {
//       return c.json({ error: 'Email and password are required' }, 400);
//     }

//     // Find user
//     const user = await prisma.user.findUnique({
//       where: {
//         email: body.email,
//       },
//       select: {
//         id: true,
//         email: true,
//         name: true,
//         password: true, // Keep password for comparison
//         role: true,
//         avatar: true,
//         bio: true,
//         createdAt: true,
//         postsCount: true,
//         receivedLikesCount: true,
//       }
//     });

//     if (!user) {
//       return c.json({ error: 'Invalid email or password' }, 401);
//     }

//     // Verify password
//     const isPasswordValid = await bcrypt.compare(body.password, user.password);

//     if (!isPasswordValid) {
//       return c.json({ error: 'Invalid email or password' }, 401);
//     }

//     // Generate JWT token
//     const token = await sign({
//       id: user.id,
//       email: user.email,
//       role: user.role
//     }, c.env.JWT_SECRET);

//     // Remove password from response
//     const { password, ...userWithoutPassword } = user;

//     return c.json({
//       message: 'Sign in successful',
//       jwt: token,
//       user: userWithoutPassword
//     });
//   } catch (error: unknown) {
//     console.error('Signin error:', error);
//     if (error instanceof Error) {
//       if (error.name === 'JWTError' || error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
//         return c.json({ error: 'Invalid or expired token during signin token generation' }, 401);
//       }
//       return c.json({ error: error.message }, 500);
//     }
//     return c.json({ error: 'Internal server error' }, 500);
//   } finally {
//     await prisma.$disconnect();
//   }
// });

userRouters.post('/signup',validate({ body: userSchema }), async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const body = await c.req.json();

    if (!body.email || !body.password) {
      return c.json({ error: 'Email and password are required' }, 400);
    }

    if (body.password.length < 6) {
      return c.json({ error: 'Password must be at least 6 characters long' }, 400);
    }

    const existingUser = await prisma.user.findFirst({
      where: { email: body.email },
    });

    if (existingUser) {
      return c.json({ error: 'User already exists with this email' }, 409);
    }

    const hashedPassword = await bcrypt.hash(body.password, 12);

    const user = await prisma.user.create({
      data: {
        name: body.name,
        email: body.email,
        password: hashedPassword,
        role: body.role === 'ADMIN' ? 'ADMIN' : 'USER',
        avatar: body.avatar,
        bio: body.bio,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatar: true,
        bio: true,
        createdAt: true,
        postsCount: true,
        receivedLikesCount: true,
      }
    });

    const token = await sign({
      id: user.id,
      email: user.email,
      role: user.role,
    }, c.env.JWT_SECRET);

    // Set cookie
    //     setCookie(c, 'jwtToken', token, {
    //     httpOnly: true,
    //     secure: c.env.NODE_ENV === 'production',
    //     maxAge: 60 * 60 * 24 * 7, // 7 days
    //     path: '/',
    //     sameSite: 'Lax',
    // });
     
    console.log('User created successfully:', user);

    return c.json({
      message: 'User created successfully',
      user,
      token
    });
  } catch (error) {
    console.error('Signup error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});

// --- Signin route ---
userRouters.post('/signin', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const body = await c.req.json();

    if (!body.email || !body.password) {
      return c.json({ error: 'Email and password are required' }, 400);
    }

    const user = await prisma.user.findUnique({
      where: { email: body.email },
      select: {
        id: true,
        email: true,
        name: true,
        password: true,
        role: true,
        avatar: true,
        bio: true,
        createdAt: true,
        postsCount: true,
        receivedLikesCount: true,
      }
    });

    if (!user || !(await bcrypt.compare(body.password, user.password))) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    const token = await sign({
      id: user.id,
      email: user.email,
      role: user.role,
    }, c.env.JWT_SECRET);

    // Remove password before sending user data back
    const { password, ...userWithoutPassword } = user;

    // Set cookie
    // setCookie(c, 'jwtToken', token, {
    //   httpOnly: true,
    //   secure: c.env.NODE_ENV === 'production',
    //   maxAge: 60 * 60 * 24 * 7, // 7 days
    //   path: '/',
    //   sameSite: 'Lax',
    // });

    return c.json({
      message: 'Sign in successful',
      user: userWithoutPassword,
      token
    });
  } catch (error) {
    console.error('Signin error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});


// --- User Profile Management Routes ---

// Get current user's OWN profile
userRouters.get('/me', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const header = c.req.header("Authorization") || "";

    if (!header) {
      return c.json({ error: "Authorization header required" }, 401);
    }

    const token = header.startsWith('Bearer ') ? header.slice(7) : header;
    const decoded = await verify(token, c.env.JWT_SECRET);

    if (!decoded || typeof decoded.id !== 'string') {
      return c.json({ error: "Invalid token or malformed payload" }, 401);
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatar: true,
        bio: true,
        createdAt: true,
        updatedAt: true,
        postsCount: true,
        receivedLikesCount: true,
      }
    });

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    return c.json({
      message: 'User profile retrieved successfully',
      user
    });
  } catch (error: unknown) {
    console.error('Get profile error:', error);
    if (error instanceof Error) {
      if (error.name === 'JWTError' || error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
        return c.json({ error: 'Invalid or expired token' }, 401);
      }
      return c.json({ error: 'Internal server error: ' + error.message }, 500);
    }
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});

// Update user profile (for the authenticated user)
userRouters.put('/me', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const header = c.req.header("Authorization") || "";

    if (!header) {
      return c.json({ error: "Authorization header required" }, 401);
    }

    const token = header.startsWith('Bearer ') ? header.slice(7) : header;
    const decoded = await verify(token, c.env.JWT_SECRET);

    if (!decoded || typeof decoded.id !== 'string') {
      return c.json({ error: "Invalid token" }, 401);
    }

    const body = await c.req.json();
    const userId = decoded.id;

    const updateData: {
      name?: string;
      avatar?: string;
      bio?: string;
      password?: string;
    } = {};

    if (body.name !== undefined) updateData.name = body.name;
    if (body.avatar !== undefined) updateData.avatar = body.avatar;
    if (body.bio !== undefined) updateData.bio = body.bio;

    if (body.currentPassword && body.newPassword) {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { password: true }
      });

      if (!user) {
        return c.json({ error: "User not found" }, 404);
      }

      const isCurrentPasswordValid = await bcrypt.compare(body.currentPassword, user.password);

      if (!isCurrentPasswordValid) {
        return c.json({ error: "Current password is incorrect" }, 400);
      }

      if (body.newPassword.length < 6) {
        return c.json({ error: 'New password must be at least 6 characters long' }, 400);
      }

      updateData.password = await bcrypt.hash(body.newPassword, 12);
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatar: true,
        bio: true,
        updatedAt: true,
        postsCount: true,
        receivedLikesCount: true,
      }
    });

    return c.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (error: unknown) {
    console.error('Update profile error:', error);
    if (error instanceof SyntaxError && error.message.includes('JSON')) {
      return c.json({ error: 'Invalid JSON body provided' }, 400);
    }
    if (error instanceof Error) {
      if (error.name === 'JWTError' || error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
        return c.json({ error: 'Invalid or expired token' }, 401);
      }
      return c.json({ error: 'Internal server error: ' + error.message }, 500);
    }
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});

// --- Admin-only Routes ---

// Get all users (Admin only)
userRouters.get('/admin/users', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const header = c.req.header("Authorization") || "";

    if (!header) {
      return c.json({ error: "Authorization header required" }, 401);
    }

    const token = header.startsWith('Bearer ') ? header.slice(7) : header;
    let decoded;
    try {
      decoded = await verify(token, c.env.JWT_SECRET);
    } catch (jwtError: unknown) {
      console.error('JWT verification error:', jwtError);
      if (jwtError instanceof Error) {
        return c.json({ error: "Invalid or expired token: " + jwtError.message }, 401);
      }
      return c.json({ error: "Invalid or expired token" }, 401);
    }

    if (!decoded || typeof decoded.id !== 'string' || decoded.role !== 'ADMIN') {
      return c.json({ error: "Admin access required" }, 403);
    }

    const page = parseInt(c.req.query('page') || '1');
    const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50);
    const skip = (page - 1) * limit;

    const [users, totalUsers] = await Promise.all([
      prisma.user.findMany({
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          avatar: true,
          createdAt: true,
          postsCount: true,
          receivedLikesCount: true,
        }
      }),
      prisma.user.count()
    ]);

    const totalPages = Math.ceil(totalUsers / limit);

    return c.json({
      message: 'Users retrieved successfully',
      data: {
        users,
        pagination: {
          currentPage: page,
          totalPages,
          pageSize: limit,
          totalUsers,
          hasMore: page < totalPages
        }
      }
    });
  } catch (error: unknown) {
    console.error('Get users error:', error);
    if (error instanceof Error) {
      if (error.name === 'JWTError' || error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
        return c.json({ error: 'Invalid or expired token' }, 401);
      }
      return c.json({ error: 'Internal server error: ' + error.message }, 500);
    }
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});

// Admin route to update user role
userRouters.put('/admin/users/:id/role', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const header = c.req.header("Authorization") || "";

    if (!header) {
      return c.json({ error: "Authorization header required" }, 401);
    }

    const token = header.startsWith('Bearer ') ? header.slice(7) : header;

    let decoded;
    try {
      decoded = await verify(token, c.env.JWT_SECRET);
    } catch (jwtError: unknown) {
      console.error('JWT verification error:', jwtError);
      if (jwtError instanceof Error) {
        return c.json({ error: "Invalid or expired token: " + jwtError.message }, 401);
      }
      return c.json({ error: "Invalid or expired token" }, 401);
    }

    if (!decoded || typeof decoded.id !== 'string' || decoded.role !== 'ADMIN') {
      return c.json({ error: "Admin access required or invalid token payload" }, 403);
    }

    const userId = c.req.param('id');
    const body = await c.req.json();

    if (!body.role || !['USER', 'ADMIN'].includes(body.role)) {
      return c.json({ error: 'Valid role (USER or ADMIN) is required' }, 400);
    }

    const existingUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true }
    });

    if (!existingUser) {
      return c.json({ error: 'User not found' }, 404);
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { role: body.role },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        updatedAt: true,
        postsCount: true,
        receivedLikesCount: true,
      }
    });

    return c.json({
      message: 'User role updated successfully',
      user: updatedUser
    });

  } catch (error: unknown) {
    console.error('Update user role error:', error);

    if (error instanceof SyntaxError && error.message.includes('JSON')) {
      return c.json({ error: 'Invalid JSON body provided' }, 400);
    }

    if (error instanceof Error) {
      if (error.name === 'JWTError' || error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
        return c.json({ error: 'Invalid or expired token' }, 401);
      }
      return c.json({ error: 'Internal server error: ' + error.message }, 500);
    }
    return c.json({ error: 'Internal server error' }, 500);

  } finally {
    await prisma.$disconnect();
  }
});

userRouters.delete('/admin/users/:id', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const header = c.req.header("Authorization") || "";

    if (!header) {
      return c.json({ error: "Authorization header required" }, 401);
    }

    const token = header.startsWith('Bearer ') ? header.slice(7) : header;

    let decoded;
    try {
      decoded = await verify(token, c.env.JWT_SECRET);
    } catch (jwtError: unknown) {
      console.error('JWT verification error:', jwtError);
      return c.json({ error: "Invalid or expired token" }, 401);
    }

    // ✅ Only allow a specific root admin
    const ROOT_ADMIN_ID = "985f34f9-1c15-4bbb-9f7a-e370dddec502";
    if (
      !decoded ||
      typeof decoded.id !== 'string' ||
      decoded.role !== 'ADMIN' ||
      decoded.id !== ROOT_ADMIN_ID // ✅ Check if it's the root admin
    ) {
      return c.json({ error: "Root admin access required" }, 403);
    }

    const userId = c.req.param('id');
    const existingUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true },
    });
    if (!existingUser) {
      return c.json({ error: 'User not found' }, 404);
    }

    await prisma.user.delete({
      where: { id: userId },
    });
    return c.json({
      message: 'User deleted successfully',
      userId,
    });
  } catch (error: unknown) {
    console.error('Delete user error:', error);

    if (error instanceof SyntaxError && error.message.includes('JSON')) {
      return c.json({ error: 'Invalid JSON body provided' }, 400);
    }

    if (error instanceof Error) {
      return c.json({ error: 'Internal server error: ' + error.message }, 500);
    }
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});

// Cloudinary signature generation endpoint
async function generateCloudinarySignature(
  paramsToSign: Record<string, string | number>,
  apiSecret: string
): Promise<string> {
  // Sort parameters by key
  const sortedParams = Object.keys(paramsToSign)
    .sort()
    .map(key => `${key}=${paramsToSign[key]}`)
    .join('&');
  
  // Create the string to sign
  const stringToSign = `${sortedParams}${apiSecret}`;
  
  // Generate SHA1 hash using Web Crypto API
  const encoder = new TextEncoder();
  const data = encoder.encode(stringToSign);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  
  // Convert to hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return hashHex;
}

// Cloudinary signature generation endpoint
userRouters.post('/imageupload', async (c) => {
  try {
    // Get environment variables
    const cloudName = c.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;
    const apiKey = c.env.CLOUDINARY_API_KEY;
    const apiSecret = c.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      return c.json({ error: 'Cloudinary configuration missing' }, 500);
    }

    const body = await c.req.json();
    const { folder } = body;

    const timestamp = Math.round((new Date()).getTime() / 1000);

    // Parameters to sign (only include folder and timestamp)
    const paramsToSign: Record<string, string | number> = {
      timestamp: timestamp,
      folder: folder || 'my_uploads',
    };

    // Generate signature using our custom function
    const signature = await generateCloudinarySignature(paramsToSign, apiSecret);

    return c.json({ 
      timestamp, 
      signature, 
      cloudname: cloudName,
      api_key: apiKey // Include API key for frontend use
    });
  } catch (error) {
    console.error('Error generating Cloudinary signature:', error);
    return c.json({ error: 'Failed to generate upload signature' }, 500);
  }
});




// --- Newsletter Routes ---

// Newsletter subscription
userRouters.post('/newsletter/subscribe', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const body = await c.req.json();

    if (!body.email) {
      return c.json({ error: 'Email is required' }, 400);
    }

    let userId: string | null = null;
    const header = c.req.header("Authorization") || "";
    if (header) {
      try {
        const token = header.startsWith('Bearer ') ? header.slice(7) : header;
        const decoded = await verify(token, c.env.JWT_SECRET);
        if (typeof decoded.id === 'string') {
          userId = decoded.id;
        }
      } catch (jwtError: unknown) {
        console.warn('JWT verification warning for newsletter subscription:', jwtError);
        // Do not block subscription for invalid token, just treat as anonymous
      }
    }

    const existingSubscription = await prisma.newsletter.findUnique({
      where: { email: body.email }
    });

    if (existingSubscription) {
      if (existingSubscription.subscribed) {
        return c.json({ message: 'Already subscribed to newsletter' }, 200);
      } else {
        await prisma.newsletter.update({
          where: { email: body.email },
          data: { subscribed: true, userId: userId }
        });
        return c.json({ message: 'Newsletter subscription reactivated' });
      }
    }

    await prisma.newsletter.create({
      data: {
        email: body.email,
        subscribed: true,
        userId: userId
      }
    });

    return c.json({ message: 'Successfully subscribed to newsletter' });
  } catch (error: unknown) {
    console.error('Newsletter subscription error:', error);
    // Duck typing for Prisma unique constraint error
    if (
      error instanceof Error && // Ensure it's an Error instance before casting
      (error as any).code === 'P2002' &&
      (error as any).meta &&
      typeof (error as any).meta.target === 'object' &&
      Array.isArray((error as any).meta.target) &&
      (error as any).meta.target.includes('email')
    ) {
      return c.json({ error: 'Email is already subscribed.' }, 409);
    }
    if (error instanceof Error) {
      return c.json({ error: 'Internal server error: ' + error.message }, 500);
    }
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});

// Newsletter unsubscription
userRouters.post('/newsletter/unsubscribe', async (c) => {
  const prisma = new PrismaClient({
    datasourceUrl: c.env.DATABASE_URL,
  }).$extends(withAccelerate());

  try {
    const body = await c.req.json();

    if (!body.email) {
      return c.json({ error: 'Email is required' }, 400);
    }

    await prisma.newsletter.upsert({
      where: { email: body.email },
      update: { subscribed: false },
      create: { email: body.email, subscribed: false }
    });

    return c.json({ message: 'Successfully unsubscribed from newsletter' });
  } catch (error: unknown) {
    console.error('Newsletter unsubscription error:', error);
    if (error instanceof Error) {
      return c.json({ error: 'Internal server error: ' + error.message }, 500);
    }
    return c.json({ error: 'Internal server error' }, 500);
  } finally {
    await prisma.$disconnect();
  }
});

