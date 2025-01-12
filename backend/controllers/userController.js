// Controller for posts route endpoints: /api/v1/users

import prisma from "../config/prismaClient.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

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

const generateJWT = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};

export default {
  asyncRegisterUser,
  asyncLoginUser,
  asyncGetUserData,
};
