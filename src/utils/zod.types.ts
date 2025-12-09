import { z } from 'zod';

// 🧍 User Schema
export const userSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100),
  email: z.string().email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters').max(100),
  role: z.enum(['USER', 'ADMIN']).default('USER'),
  avatar: z.string().url('Invalid URL').optional(),
  bio: z.string().max(500, 'Bio cannot exceed 500 characters').optional(),
});

// 📝 Blog Schema
export const blogSchema = z.object({
  title: z.string().min(5, 'Title must be at least 5 characters').max(200),
  content: z.string().min(20, 'Content must be at least 20 characters'),
  authorId: z.string().uuid('Invalid author ID'),
  tags: z.array(z.string().min(2).max(50)).optional(),
  published: z.boolean().default(false),
  coverImage: z.string().url('Invalid URL').optional(),
});

// 🔐 Login Schema
export const loginSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(6, 'Password must be at least 6 characters').max(100),
});

// 🧍 Update User Schema
export const updateUserSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  avatar: z.string().url('Invalid URL').optional(),
  bio: z.string().max(500).optional(),
});

// 📝 Update Blog Schema
export const updateBlogSchema = z.object({
  title: z.string().min(5).max(200).optional(),
  content: z.string().min(20).optional(),
  tags: z.array(z.string().min(2).max(50)).optional(),
  published: z.boolean().optional(),
  coverImage: z.string().url('Invalid URL').optional(),
});

// ✅ Export types for strong inference in routes or services
export type UserType = z.infer<typeof userSchema>;
export type BlogType = z.infer<typeof blogSchema>;
export type LoginType = z.infer<typeof loginSchema>;
export type UpdateUserType = z.infer<typeof updateUserSchema>;
export type UpdateBlogType = z.infer<typeof updateBlogSchema>;
