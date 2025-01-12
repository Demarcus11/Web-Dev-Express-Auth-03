// User route endpoints

import express from "express";
import userController from "../controllers/userController.js";
import protect from "../middleware/auth.js";

const userRouter = express.Router();

// User endpoints
userRouter.post("/", userController.asyncRegisterUser);
userRouter.post("/login", userController.asyncLoginUser);
userRouter.get("/me", protect, userController.asyncGetUserData);

export default userRouter;
