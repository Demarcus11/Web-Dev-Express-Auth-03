// Controller for posts route endpoints: /api/v1/posts

import prisma from "../config/prismaClient.js";

/* @desc      Get all posts
   @endpoint  GET /posts
   @access    Private
*/
export const asyncGetAllPosts = async (req, res) => {
  // ensures limit is non-negative, if limit isn't a valid number then set limit to all posts, else set limit to there limit the client set
  const limit = Math.max(
    0,
    isNaN(parseInt(req.query.limit)) ? Infinity : parseInt(req.query.limit)
  );

  let posts;

  try {
    posts = await prisma.post.findMany({
      where: {
        created_by: req.user.id,
      },
    });
  } catch (e) {
    console.error(e);
  }

  res.status(200).json(posts.slice(0, limit));
};

/* @desc      Get single post
   @endpoint  GET /posts/:id
   @access    Private
*/
export const asyncGetPost = async (req, res, next) => {
  const id = parseInt(req.params.id);

  let post;

  try {
    post = await prisma.post.findUnique({
      where: {
        id,
      },
    });

    if (!post) {
      const err = new Error(`No post with id ${req.params.id} was found`);
      err.status = 404;
      return next(err);
    }

    // if the post exists, make sure only the post created by the authenticated user can access the post
    if (post.created_by !== req.user.id) {
      const err = new Error("You are not authorized to view this post");
      err.status = 401;
      return next(err);
    }
  } catch (e) {
    console.error(e);
  }

  res.status(200).json(post);
};

/* @desc      Create a post
   @endpoint  POST /posts
   @access    Private
*/
export const asyncCreatePost = async (req, res, next) => {
  const { title, body } = req.body;

  if (!title) {
    const err = new Error(`Please include a title field`);
    err.status = 404;
    next(err);
    return;
  }

  let post;

  try {
    post = await prisma.post.create({
      data: {
        title,
        body,
        postAuthor: {
          connect: {
            id: req.user.id,
          },
        },
      },
    });
  } catch (e) {
    console.error(e);
  }

  res.status(201).json(post);
};

/* @desc      Update a post
   @endpoint  PATCH posts/:id
   @access    Private
*/
export const asyncUpdatePost = async (req, res, next) => {
  const { title, body } = req.body;
  const id = parseInt(req.params.id);

  let post;

  try {
    post = await prisma.post.findUnique({
      where: {
        id,
      },
    });

    if (!post) {
      const err = new Error(`No post with id ${req.params.id} was found`);
      err.status = 404;
      return next(err);
    }

    // if the post exists, make sure only the post created by the authenticated user can access the post
    if (post.created_by !== req.user.id) {
      const err = new Error("You are not authorized to update this post");
      err.status = 401;
      return next(err);
    }

    post = await prisma.post.update({
      where: {
        id,
      },
      data: {
        title,
        body,
      },
    });
  } catch (e) {
    console.error(e);
  }

  res.status(200).json(post);
};

/* @desc      Delete a post
   @endpoint  DELETE /posts/:id
   @access    Private
*/
export const asyncDeletePost = async (req, res, next) => {
  const id = parseInt(req.params.id);

  let post;

  try {
    post = await prisma.post.findUnique({
      where: {
        id,
      },
    });

    if (!post) {
      const err = new Error(`No post with id ${req.params.id} was found`);
      err.status = 404;
      return next(err);
    }

    // if the post exists, make sure only the post created by the authenticated user can access the post
    if (post.created_by !== req.user.id) {
      const err = new Error("You are not authorized to delete this post");
      err.status = 401;
      return next(err);
    }

    post = await prisma.post.delete({
      where: {
        id,
      },
    });
  } catch (e) {
    console.error(e);
  }

  res.status(204).json();
};

export default {
  asyncGetAllPosts,
  asyncGetPost,
  asyncCreatePost,
  asyncUpdatePost,
  asyncDeletePost,
};
