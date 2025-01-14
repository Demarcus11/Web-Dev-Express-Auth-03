// Controller for posts route endpoints: /api/v1/users

import prisma from "../config/prismaClient.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import asyncSendEmail from "../utils/sendEmail.js";
import generateJWT from "../utils/generateJWT.js";

/* @desc      Register a user
   @endpoint  POST /users
   @access    Public
*/
export const asyncRegisterUser = async (req, res, next) => {
  const { username, email, password } = req.body;

  let user;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });
  } catch (e) {
    console.error(e);

    if (e.code === "P2002") {
      const err = new Error("Email or username already exists.");
      err.status = 400;
      return next(err);
    } else {
      const err = new Error("Please include all fields.");
      err.status = 400;
      return next(err);
    }
  }

  res.status(201).json({
    id: user.id,
    username: user.username,
    email: user.email,
    token: generateJWT(user.id),
  });
};

/* @desc      Authenticate a user 
   @endpoint  POST /users/login
   @access    Public
*/
export const asyncLoginUser = async (req, res, next) => {
  const { username, password } = req.body;

  let user;

  try {
    user = await prisma.user.findUnique({
      where: { username },
    });

    if (user && (await bcrypt.compare(password, user.password))) {
      return res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        token: generateJWT(user.id),
      });
    } else {
      const err = new Error("Couldn't find your account.");
      err.status = 401;
      return next(err);
    }
  } catch (e) {
    console.error(e);
  }
};

/* @desc      Get logged in user data
   @endpoint  GET /users/me
   @access    Private
*/
export const asyncGetUserData = async (req, res, next) => {
  const { id, username, email } = await prisma.user.findUnique({
    where: {
      id: req.user.id,
    },
  });

  res.status(200).json({ id, username, email });
};

/* @desc      Send password reset token
   @endpoint  POST /users/forgot-password
   @access    Public
*/
const asyncForgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      const err = new Error("Couldn't find your account.");
      err.status = 404;
      return next(err);
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 1000 * 60 * 10);

    await prisma.user.update({
      where: {
        email,
      },
      data: {
        passwordResetToken: resetToken,
        passwordResetTokenExpiry: resetTokenExpiry,
      },
    });

    const resetLink = `${req.protocol}://${req.get(
      "host"
    )}/api/v1/users/reset-password/${resetToken}`;

    await asyncSendEmail({
      to: email,
      subject: "Password reset",
      text: `Password reset link: ${resetLink}`,
    });
  } catch (e) {
    console.error(e);
  }

  res.status(200).json({ msg: "Password reset link sent to your email." });
};

/* @desc      Reset user password
   @endpoint  POST /users/forgot-password/:token
   @access    Public
*/
export const asyncResetPassword = async (req, res, next) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: token,
        passwordResetTokenExpiry: {
          gte: new Date(),
        },
      },
    });

    if (!user) {
      const err = new Error("Invalid or expired token.");
      err.status = 400;
      return next(err);
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetTokenExpiry: null,
      },
    });
  } catch (e) {
    console.error(e);
  }

  res.status(200).json({ msg: "Password has been reset successfully." });
};

export default {
  asyncRegisterUser,
  asyncLoginUser,
  asyncGetUserData,
  asyncForgotPassword,
  asyncResetPassword,
};
