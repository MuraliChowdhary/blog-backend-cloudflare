import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client/edge';
import { withAccelerate } from '@prisma/extension-accelerate';
import { verify } from 'hono/jwt';
export const blogRouter = new Hono();
// --- Middleware for Authentication (Optional for Public Routes) ---
blogRouter.use("/*", async (c, next) => {
    const header = c.req.header("Authorization") || "";
    c.set("userId", undefined); // Reset context for each request
    c.set("userRole", undefined);
    if (header) {
        try {
            const token = header.startsWith('Bearer ') ? header.slice(7) : header;
            const decodedUser = await verify(token, c.env.JWT_SECRET); // Renamed to avoid confusion with Prisma user object
            if (decodedUser && typeof decodedUser.id === 'string' && (decodedUser.role === 'ADMIN' || decodedUser.role === 'USER')) {
                const prisma = new PrismaClient({
                    datasourceUrl: c.env.DATABASE_URL,
                }).$extends(withAccelerate());
                // Verify the user still exists and their role is valid
                const userDetails = await prisma.user.findUnique({
                    where: { id: decodedUser.id },
                    select: { id: true, role: true }
                });
                if (userDetails) {
                    c.set("userId", userDetails.id);
                    c.set("userRole", userDetails.role);
                }
                else {
                    console.warn("Authenticated user not found in DB or role mismatch.");
                    // If user in token is not found, treat as unauthenticated
                }
            }
        }
        catch (error) {
            console.warn("JWT verification failed, treating as unauthenticated:", error);
            // Do not return 401 here directly, let the route decide if auth is required
        }
    }
    await next(); // Proceed to the next middleware or route handler
});
// Admin-only middleware - now simpler, relies on 'userRole' being set by the main middleware
const adminOnly = async (c, next) => {
    const userRole = c.get("userRole");
    if (userRole !== "ADMIN") {
        return c.json({ error: "Admin access required" }, 403);
    }
    await next();
};
// --- Admin-only Post Management Routes ---
// Create new post (Admin only)
blogRouter.post('/', adminOnly, async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const body = await c.req.json();
        const authorId = c.get("userId"); // Guaranteed to be present by adminOnly middleware
        // Validate required fields
        if (!body.title || !body.content) {
            return c.json({ error: 'Title and content are required for a post.' }, 400);
        }
        // Generate slug from title if not provided
        const slug = body.slug || body.title.toLowerCase()
            .replace(/[^a-zA-Z0-9\s]/g, '')
            .replace(/\s+/g, '-');
        const postBlog = await prisma.post.create({
            data: {
                title: body.title,
                content: body.content,
                excerpt: body.excerpt,
                published: body.published || false,
                featured: body.featured || false,
                imageUrl: body.imageUrl,
                slug: slug,
                tags: body.tags || [],
                readTime: body.readTime,
                authorId: authorId, // `authorId` is guaranteed by `adminOnly`
                publishedAt: body.published ? new Date() : null
            }
        });
        // Increment postsCount on the author's User model
        await prisma.user.update({
            where: { id: authorId },
            data: { postsCount: { increment: 1 } }
        });
        return c.json({
            message: "Successfully created the post",
            id: postBlog.id,
            slug: postBlog.slug
        });
    }
    catch (err) {
        console.error('Create post error:', err);
        if (err.code === 'P2002') {
            return c.json({ error: "Slug already exists" }, 409);
        }
        if (err instanceof SyntaxError && err.message.includes('JSON')) {
            return c.json({ error: 'Invalid JSON body provided' }, 400);
        }
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// Update post (Admin only)
blogRouter.put('/:id', adminOnly, async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const body = await c.req.json();
        const postId = c.req.param("id");
        const updateData = {
            updatedAt: new Date()
        };
        // Only update fields if they are provided in the body
        if (body.title !== undefined)
            updateData.title = body.title;
        if (body.content !== undefined)
            updateData.content = body.content;
        if (body.excerpt !== undefined)
            updateData.excerpt = body.excerpt;
        if (body.published !== undefined)
            updateData.published = body.published;
        if (body.featured !== undefined)
            updateData.featured = body.featured;
        if (body.imageUrl !== undefined)
            updateData.imageUrl = body.imageUrl;
        if (body.tags !== undefined)
            updateData.tags = body.tags;
        if (body.readTime !== undefined)
            updateData.readTime = body.readTime;
        if (body.slug) {
            updateData.slug = body.slug;
        }
        // Set publishedAt if published is true and it wasn't already set
        // Or clear it if published is false
        const currentPost = await prisma.post.findUnique({
            where: { id: postId },
            select: { publishedAt: true }
        });
        if (body.published === true && !currentPost?.publishedAt) {
            updateData.publishedAt = new Date();
        }
        else if (body.published === false) {
            updateData.publishedAt = null; // Clear publishedAt if unpublished
        }
        const postBlog = await prisma.post.update({
            where: { id: postId },
            data: updateData
        });
        return c.json({
            message: "Successfully updated the post",
            id: postBlog.id,
            slug: postBlog.slug
        });
    }
    catch (err) {
        console.error('Update post error:', err);
        if (err.code === 'P2002') {
            return c.json({ error: "Slug already exists" }, 409);
        }
        if (err.code === 'P2025') { // Handle "record not found" if post ID is invalid
            return c.json({ error: "Post not found" }, 404);
        }
        if (err instanceof SyntaxError && err.message.includes('JSON')) {
            return c.json({ error: 'Invalid JSON body provided' }, 400);
        }
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// Delete post (Admin only)
blogRouter.delete('/:id', adminOnly, async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const postId = c.req.param("id");
        // Before deleting the post, get its authorId to decrement postsCount
        const postToDelete = await prisma.post.findUnique({
            where: { id: postId },
            select: { authorId: true }
        });
        if (!postToDelete) {
            return c.json({ error: "Post not found" }, 404);
        }
        await prisma.post.delete({
            where: { id: postId }
        });
        // Decrement postsCount on the author's User model
        if (postToDelete.authorId) {
            await prisma.user.update({
                where: { id: postToDelete.authorId },
                data: { postsCount: { decrement: 1 } }
            });
        }
        return c.json({
            message: "Successfully deleted the post"
        });
    }
    catch (err) {
        console.error('Delete post error:', err);
        if (err.code === 'P2025') { // Handle "record not found"
            return c.json({ error: "Post not found" }, 404);
        }
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// --- Public Access Routes ---
// Get all posts with enhanced filtering and pagination
blogRouter.get('/bulk', async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const page = parseInt(c.req.query('page') || '1');
        const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50); // Max 50 per page
        const skip = (page - 1) * limit;
        // Filters
        const published = c.req.query('published') !== 'false';
        const featured = c.req.query('featured') === 'true';
        const tag = c.req.query('tag');
        const search = c.req.query('search');
        const whereClause = { published };
        if (featured)
            whereClause.featured = true;
        if (tag)
            whereClause.tags = { has: tag };
        if (search) {
            whereClause.OR = [
                { title: { contains: search, mode: 'insensitive' } },
                { content: { contains: search, mode: 'insensitive' } },
                { excerpt: { contains: search, mode: 'insensitive' } }
            ];
        }
        const [posts, totalPosts] = await Promise.all([
            prisma.post.findMany({
                where: whereClause,
                skip,
                take: limit,
                orderBy: [
                    { featured: 'desc' },
                    { publishedAt: 'desc' },
                    { createdAt: 'desc' }
                ],
                select: {
                    id: true,
                    title: true,
                    excerpt: true,
                    imageUrl: true,
                    slug: true,
                    tags: true,
                    readTime: true,
                    viewCount: true,
                    featured: true,
                    publishedAt: true,
                    createdAt: true,
                    commentsCount: true, // Use the pre-calculated count
                    likesCount: true, // Use the pre-calculated count
                    author: {
                        select: {
                            id: true,
                            name: true,
                            avatar: true
                        }
                    },
                }
            }),
            prisma.post.count({ where: whereClause })
        ]);
        const totalPages = Math.ceil(totalPosts / limit);
        const hasMore = page < totalPages;
        return c.json({
            status: "success",
            data: {
                posts,
                pagination: {
                    currentPage: page,
                    totalPages,
                    pageSize: limit,
                    totalPosts,
                    hasMore
                }
            }
        });
    }
    catch (err) {
        console.error('Get posts error:', err);
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// Get single post by ID or slug
blogRouter.get('/:identifier', async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const identifier = c.req.param("identifier");
        const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identifier);
        const whereClause = isUuid ? { id: identifier } : { slug: identifier };
        const blog = await prisma.post.findFirst({
            where: {
                ...whereClause,
                published: true // Only show published posts
            },
            select: {
                id: true,
                title: true,
                content: true,
                excerpt: true,
                imageUrl: true,
                slug: true,
                tags: true,
                readTime: true,
                viewCount: true,
                featured: true,
                publishedAt: true,
                createdAt: true,
                commentsCount: true, // Use the pre-calculated count
                likesCount: true, // Use the pre-calculated count
                author: {
                    select: {
                        id: true,
                        name: true,
                        avatar: true,
                        bio: true
                    }
                },
                comments: {
                    where: { parentId: null }, // Only top-level comments
                    orderBy: { createdAt: 'desc' },
                    take: 10,
                    select: {
                        id: true,
                        content: true,
                        createdAt: true,
                        // Include guest specific fields for comments
                        isGuest: true,
                        guestName: true,
                        guestEmail: true,
                        author: {
                            select: {
                                id: true,
                                name: true,
                                avatar: true
                            }
                        },
                        replies: {
                            take: 3,
                            orderBy: { createdAt: 'asc' },
                            select: {
                                id: true,
                                content: true,
                                createdAt: true,
                                // Include guest specific fields for replies
                                isGuest: true,
                                guestName: true,
                                guestEmail: true,
                                author: {
                                    select: {
                                        id: true,
                                        name: true,
                                        avatar: true
                                    }
                                }
                            }
                        }
                    }
                },
            }
        });
        if (!blog) {
            return c.json({ error: "Post not found or not published" }, 404);
        }
        // Increment view count
        await prisma.post.update({
            where: { id: blog.id },
            data: { viewCount: { increment: 1 } }
        });
        return c.json({
            message: "Successfully retrieved the post",
            data: blog
        });
    }
    catch (err) {
        console.error('Get post error:', err);
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// Like/Unlike post (handles both authenticated users and guests)
blogRouter.post('/:id/like', async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const postId = c.req.param("id");
        const authenticatedUserId = c.get("userId"); // Will be `undefined` if not logged in
        // Find the post to ensure it exists and get its authorId for updating receivedLikesCount
        const post = await prisma.post.findUnique({
            where: { id: postId },
            select: { id: true, authorId: true }
        });
        if (!post) {
            return c.json({ error: "Post not found" }, 404);
        }
        let existingLike;
        if (authenticatedUserId) {
            // For authenticated users, check by userId and postId
            existingLike = await prisma.like.findUnique({
                where: {
                    userId_postId: {
                        userId: authenticatedUserId,
                        postId: postId
                    }
                }
            });
        }
        else {
            // For guests, we can't reliably prevent duplicate likes without client-side tracking (e.g., cookie ID)
            // For simplicity, we'll allow multiple guest likes for now, or you can require a simple captcha/guestIdentifier.
            // If you implement guestIdentifier, you'd findUnique based on { guestIdentifier_postId }
            existingLike = null; // Guests don't have a unique constraint on (guestId, postId) in schema
        }
        if (existingLike) {
            // Unlike
            await prisma.like.delete({
                where: { id: existingLike.id }
            });
            // Decrement likesCount on the Post
            await prisma.post.update({
                where: { id: postId },
                data: { likesCount: { decrement: 1 } }
            });
            // Decrement receivedLikesCount on the author's User model
            if (post.authorId) {
                await prisma.user.update({
                    where: { id: post.authorId },
                    data: { receivedLikesCount: { decrement: 1 } }
                });
            }
            return c.json({ message: "Post unliked", liked: false });
        }
        else {
            // Like
            const newLike = await prisma.like.create({
                data: {
                    postId: postId,
                    userId: authenticatedUserId, // Will be null for guests
                    isGuest: !authenticatedUserId // True if userId is null
                }
            });
            // Increment likesCount on the Post
            await prisma.post.update({
                where: { id: postId },
                data: { likesCount: { increment: 1 } }
            });
            // Increment receivedLikesCount on the author's User model
            if (post.authorId) {
                await prisma.user.update({
                    where: { id: post.authorId },
                    data: { receivedLikesCount: { increment: 1 } }
                });
            }
            return c.json({ message: "Post liked", liked: true, likeId: newLike.id });
        }
    }
    catch (err) {
        console.error('Like post error:', err);
        // Handle unique constraint failure for authenticated users if they try to like twice
        if (err.code === 'P2002' && err.meta?.target?.includes('userId_postId')) {
            return c.json({ error: "User already liked this post." }, 409);
        }
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// Add comment to post (handles both authenticated users and guests)
blogRouter.post('/:id/comments', async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const postId = c.req.param("id");
        const authenticatedUserId = c.get("userId"); // Will be `undefined` if not logged in
        const body = await c.req.json();
        // Validate content
        if (!body.content || typeof body.content !== 'string' || body.content.trim() === '') {
            return c.json({ error: 'Comment content is required.' }, 400);
        }
        // Determine if it's a guest comment
        let isGuest = true;
        let guestName = null;
        let guestEmail = null;
        if (authenticatedUserId) {
            isGuest = false;
        }
        else {
            // For guests, require a guestName
            if (!body.guestName || typeof body.guestName !== 'string' || body.guestName.trim() === '') {
                return c.json({ error: 'Guest comments require a name.' }, 400);
            }
            guestName = body.guestName.trim();
            guestEmail = typeof body.guestEmail === 'string' && body.guestEmail.trim() !== '' ? body.guestEmail.trim() : null;
        }
        // Check if post exists
        const post = await prisma.post.findUnique({
            where: { id: postId },
            select: { id: true }
        });
        if (!post) {
            return c.json({ error: "Post not found" }, 404);
        }
        // Check if parent comment exists if parentId is provided
        if (body.parentId) {
            const parentComment = await prisma.comment.findUnique({
                where: { id: body.parentId },
                select: { id: true, postId: true }
            });
            if (!parentComment || parentComment.postId !== postId) {
                return c.json({ error: "Invalid parent comment ID for this post." }, 400);
            }
        }
        const comment = await prisma.comment.create({
            data: {
                content: body.content,
                postId: postId,
                parentId: body.parentId || null,
                authorId: authenticatedUserId, // Null for guests
                isGuest: isGuest,
                guestName: guestName, // Null for logged-in users
                guestEmail: guestEmail, // Null for logged-in users
            },
            select: {
                id: true,
                content: true,
                createdAt: true,
                isGuest: true,
                guestName: true,
                guestEmail: true,
                author: {
                    select: {
                        id: true,
                        name: true,
                        avatar: true
                    }
                },
                parentId: true // Include parentId if it's a reply
            }
        });
        // Increment commentsCount on the Post
        await prisma.post.update({
            where: { id: postId },
            data: { commentsCount: { increment: 1 } },
        });
        return c.json({
            message: "Comment added successfully",
            data: comment
        }, 201); // 201 Created
    }
    catch (err) {
        console.error('Add comment error:', err);
        if (err instanceof SyntaxError && err.message.includes('JSON')) {
            return c.json({ error: 'Invalid JSON body provided' }, 400);
        }
        // Handle Prisma error if post or parent ID is invalid
        if (err.code === 'P2003') { // Foreign key constraint failed
            return c.json({ error: "Post or parent comment not found." }, 404);
        }
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// Delete comment (Author or Admin only) - New route for deletion
blogRouter.delete('/comments/:commentId', async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const commentId = c.req.param('commentId');
        const authenticatedUserId = c.get('userId');
        const userRole = c.get('userRole');
        // Find the comment and its associated post and author
        const comment = await prisma.comment.findUnique({
            where: { id: commentId },
            select: {
                id: true,
                authorId: true,
                isGuest: true,
                postId: true
            }
        });
        if (!comment) {
            return c.json({ error: 'Comment not found.' }, 404);
        }
        // Authorization check: Only author or admin can delete
        if (!authenticatedUserId || (comment.authorId !== authenticatedUserId && userRole !== 'ADMIN')) {
            return c.json({ error: 'Unauthorized to delete this comment.' }, 403);
        }
        // If it's a guest comment, ensure no authenticated user is trying to delete someone else's guest comment
        // (This is implicitly handled by the above check if `comment.authorId` is null for guests)
        await prisma.comment.delete({
            where: { id: commentId }
        });
        // Decrement commentsCount on the Post
        await prisma.post.update({
            where: { id: comment.postId },
            data: { commentsCount: { decrement: 1 } }
        });
        return c.json({ message: 'Comment deleted successfully.' }, 200);
    }
    catch (err) {
        console.error('Delete comment error:', err);
        if (err.code === 'P2025') { // Comment not found by ID
            return c.json({ error: "Comment not found." }, 404);
        }
        return c.json({ error: 'Internal server error.' }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
// Get comments for a post (Public access) - no changes here apart from select fields
blogRouter.get('/:id/comments', async (c) => {
    const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    try {
        const postId = c.req.param("id");
        const page = parseInt(c.req.query('page') || '1');
        const limit = Math.min(parseInt(c.req.query('limit') || '10'), 20);
        const skip = (page - 1) * limit;
        const comments = await prisma.comment.findMany({
            where: {
                postId: postId,
                parentId: null
            },
            skip,
            take: limit,
            orderBy: { createdAt: 'desc' },
            select: {
                id: true,
                content: true,
                createdAt: true,
                isGuest: true, // Include guest specific fields
                guestName: true,
                guestEmail: true,
                author: {
                    select: {
                        id: true,
                        name: true,
                        avatar: true
                    }
                },
                replies: {
                    take: 5,
                    orderBy: { createdAt: 'asc' },
                    select: {
                        id: true,
                        content: true,
                        createdAt: true,
                        isGuest: true, // Include guest specific fields for replies
                        guestName: true,
                        guestEmail: true,
                        author: {
                            select: {
                                id: true,
                                name: true,
                                avatar: true
                            }
                        }
                    }
                }
            }
        });
        return c.json({
            status: "success",
            data: comments
        });
    }
    catch (err) {
        console.error('Get comments error:', err);
        return c.json({ error: "Internal server error" }, 500);
    }
    finally {
        await prisma.$disconnect();
    }
});
