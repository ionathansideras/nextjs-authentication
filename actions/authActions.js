"use server";
import { createUser, getUserByEmail } from "@/lib/user";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { redirect } from "next/navigation";
import { createAuthSession, destroySession } from "@/lib/auth";

export async function signUp(prevFormState, formData) {
    const email = formData.get("email");
    const password = formData.get("password");

    let errors = {};

    if (!email.includes("@")) {
        errors.email = "Invalid email address";
    }

    if (password.trim().length < 8) {
        errors.password = "Password must be at least 8 characters long";
    }

    if (Object.keys(errors).length > 0) {
        return { errors };
    }

    const hashedPassword = hashUserPassword(password);

    try {
        const userId = createUser(email, hashedPassword);
        await createAuthSession(userId);
        redirect("/training");
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            errors.email = "Email already in use";
            return { errors };
        }

        throw error;
    }
}

export async function login(prevFormState, formData) {
    const email = formData.get("email");
    const password = formData.get("password");

    const existingUser = getUserByEmail(email);

    if (!existingUser) {
        return { errors: { email: "email not found" } };
    }

    const isValidPassword = verifyPassword(existingUser.password, password);

    if (!isValidPassword) {
        return { errors: { password: "invalid password" } };
    }

    await createAuthSession(existingUser.id);
    redirect("/training");
}

export async function authMode(mode, prevFormState, formData) {
    return mode === "login"
        ? login(prevFormState, formData)
        : signUp(prevFormState, formData);
}

export async function logout() {
    await destroySession();
    redirect("/");
}
