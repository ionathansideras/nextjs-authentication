// Import necessary modules
import { Lucia } from "lucia";
import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import { cookies } from "next/headers";

// Import the database instance
import db from "./db";

// Create a new SQLite adapter for Lucia
const adapter = new BetterSqlite3Adapter(db, {
    user: "users", // Specify the users table
    session: "sessions", // Specify the sessions table
});

// Create a new Lucia instance with the SQLite adapter and session cookie settings
const lucia = new Lucia(adapter, {
    sessionCookie: {
        expires: false, // Session cookies do not expire
        attributes: {
            secure: process.env.NODE_ENV === "production", // Use secure cookies in production
        },
    },
});

// Function to create a new authentication session
export async function createAuthSession(userId) {
    // Create a new session for the user
    const session = await lucia.createSession(userId, {});
    // Create a new session cookie
    const sessionCookie = lucia.createSessionCookie(session.id);
    // Set the session cookie
    cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
    );
}

// Function to verify the authentication of a user
export async function verifyAuth() {
    // Get the session cookie
    const sessionCookie = cookies().get(lucia.sessionCookieName);

    // If there's no session cookie, return null user and session
    if (!sessionCookie) {
        return {
            user: null,
            session: null,
        };
    }

    // Get the session ID from the cookie
    const sessionId = sessionCookie.value;

    // If there's no session ID, return null user and session
    if (!sessionId) {
        return {
            user: null,
            session: null,
        };
    }

    // Validate the session
    const result = await lucia.validateSession(sessionId);

    try {
        // If the session is valid and fresh, set a new session cookie
        if (result.session && result.session.fresh) {
            const sessionCookie = lucia.createSessionCookie(result.session.id);
            cookies().set(
                sessionCookie.name,
                sessionCookie.value,
                sessionCookie.attributes
            );
        }

        // If there's no session, set a blank session cookie
        if (!result.session) {
            const sessionCookie = lucia.createBlankSessionCookie();
            cookies().set(
                sessionCookie.name,
                sessionCookie.value,
                sessionCookie.attributes
            );
        }
    } catch {}

    // Return the result of the session validation
    return result;
}

// Function to end the current authentication session
export async function destroySession() {
    const { session } = await verifyAuth();
    if (!session)
        return {
            error: "No session found",
        };

    await lucia.invalidateSession(session.id);

    const sessionCookie = lucia.createBlankSessionCookie();
    cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
    );
}
