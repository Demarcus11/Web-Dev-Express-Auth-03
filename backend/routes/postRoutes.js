// Post route endpoints

import express from "express";
import postsController from "../controllers/postController.js";
import protect from "../middleware/auth.js";

const postsRouter = express.Router();

// Posts endpoints
postsRouter.get("/", protect, postsController.asyncGetAllPosts);
postsRouter.get("/:id", protect, postsController.asyncGetPost);
postsRouter.post("/", protect, postsController.asyncCreatePost);
postsRouter.patch("/:id", protect, postsController.asyncUpdatePost);
postsRouter.delete("/:id", protect, postsController.asyncDeletePost);

export default postsRouter;
