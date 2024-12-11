import Credentials from "next-auth/providers/credentials";
import NextAuth from "next-auth";
import { z } from "zod";
import { sql } from "@vercel/postgres";
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcryptjs';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    
    return user.rows[0];
  } catch (error) {
    console.error('Failed to featch user: ', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { signIn, handlers, auth, signOut } = NextAuth({
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);

          if (!user) {
            return null;
          }

          const passwordMatch = await bcrypt.compare(password, user.password);

          if (passwordMatch) {
            return user;
          }
        }

        return null;
      },
    }),
  ],
  pages: {
    signIn: "/login",
  },
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = Boolean(auth?.user);
      const isOnDashboard = nextUrl.pathname.startsWith("/dashboard");

      if (!isOnDashboard) {
        if (isLoggedIn) {
          return Response.redirect(new URL("/dashboard", nextUrl));
        }
        return true;
      }

      return isLoggedIn;
    },
  },
});
