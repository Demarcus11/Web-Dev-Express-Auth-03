import express from "express";
import path from "path";
import errorHandler from "./middleware/error.js";
import postsRouter from "./routes/postRoutes.js";
import userRouter from "./routes/userRoutes.js";

const app = express(); // Create HTTP Server

app.use(express.json()); // middleware for the server to parse raw JSON data from request body
app.use(express.urlencoded({ extended: false })); // middleware for the server to parse Form-encoded data from request body
app.use(express.static(path.join(import.meta.dirname, "public"))); // Middleware for static folder, express.static() takes in an absolute path to the static folder

// Routes
app.use("/api/v1/posts", postsRouter);
app.use("/api/v1/users", userRouter);

// app level middleware for invalid routes
app.use((req, res, next) => {
  const error = new Error("Not Found");
  error.status = 404;
  next(error);
});

app.use(errorHandler); // app level middleware for endpoint errors

// Start HTTP Server
app.listen(process.env.PORT, () => {
  console.log(
    `Server running on localhost and listening on PORT ${
      process.env.PORT || 8000
    }...`
  );
});
