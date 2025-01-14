# Auth

In the last module we left off by creating the user routes and controller skeletons. In the modules we'll add the logic to authenticate users, register users, and login users to those controllers.

## JWT (Json Web Tokens)

Some routes shouldn't be able to be hit by any client that makes a request. In our case, we don't want unauthorized users to hit the route /users/me because we dont want anybody accessing a specfic users data except for the authorized user. The routes /users and /users/login are public because any client should be able to register and try to login.

We're going to use web tokens to authorize users, specifically, json web tokens. A JWT looks like this: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

This long token is broken up into 3 parts: header, payload, and signature. Each part has data that is encrypted into the token. When the data changes the token changes.

- Header: encryption algorithm and token type

  Default enryption algorithm is HS256, but there's many others such as HS384, HS512, etc.

  {
  "alg": "HS256", <--- if you change the encrpyption alogrithm then the header part of the token would change
  "typ": "JWT"
  }

- Payload: data

  You can have whatever you want in the payload, in our case we're going to have a user id.

  {
  "sub": "1234567890", <--- subject (whom the token refers to)
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022 <--- issued at (seconds since Unix epoch)
  }

- Signature

  The signature is a combination of the header, payload, and 384-bit secret that you can generate (always different). It makes sure the JWT hasn't been tempered with because the token the client is using should match the token on the server.

To install jwt: `npm i jsonwebtoken`

## Register User Logic

When registering a user, we aren't going to store plain text passwords in the database for security purposes. We're going to hash the password to encrypt them and store the hashed password in the DB. To do this, we're going to use bcryptjs: `npm i bcryptjs`. This will be done in the register user controller:

```js
// userController.js

import prisma from "../config/prismaClient.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

/* @desc      Register a user
   @endpoint  POST /users
   @access    Public
*/
export const asyncRegisterUser = async (req, res, next) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    const err = new Error("Please include all fields");
    err.status = 400;
    return next(err);
  }

  let user;

  try {
    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // create user
    user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });
  } catch (e) {
    console.error(e);

    // handle errors
    if (e.code === "P2002") {
      const err = new Error("Email or username already exists.");
      err.status = 400;
      return next(err);
    } else {
      const err = new Error("Invalid user data.");
      err.status = 400;
      return next(err);
    }
  }

  res.status(201).json(user);
};
```

## Log-in User Logic

We find if the username exists, if so then check if the password is valid, if so then send the user data as a response.

```JS
/* @desc      Authenticate a user
   @endpoint  POST /users/login
   @access    Public
*/
export const asyncLoginUser = async (req, res, next) => {
  const { username, password } = req.body;

  let user;

  try {
    user = await prisma.user.findUnique({ where: { username } });

    if (user && (await bcrypt.compare(password, user.password))) {
      return res.json(user);
    } else {
      const err = new Error("Couldn't find your account.");
      err.status = 401;
      return next(err);
    }
  } catch (e) {
    console.error(e);
  }

  res.status(200).json({ msg: "Login User" });
};
```

## JWT

Now, we can get into the JWT. We'll need to sign the token and send the token as a response to register and login. First, we'll need a secret in the .env. You can use a JWT secret generator such as https://jwtsecret.com/generate to generate a secret.

Since were going to generate a JWT when the user registers or logs in we can create a function so we dont have to write the same code twice and have an easier time debugging if something goes wrong:

```JS
// userController.js

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

  // send back user data and JWT as the response
  res.status(201).json({
    ...user,
    token: generateJWT(user.id),
  });
};

const generateJWT = (id) => {
  // sign() takes in a payload, secret, and options. We are sending the user's id as the payload ()
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};
```

## Protect routes

When a client sends a request to a protected route, the server has to identify them. In order for the server to identify them the client must have a JWT in their request. Remember, the JWT has a payload with data about the user that it was created for such as an id, email, role, etc. The frontend will save the the JWT it got from when the user logged in/registered and use it for making requests to protected routes. The frontend will use the authorization attribute under the request headers object and set its value the "Bearer <JWT>". When the server recieves the request, it will looks inside the authorization attribute and retrieve the JWT. The server will verify/decode the JWT to access the payload data and store it inside of req.user. If the verfiy fails then the user is unauthorized. If the verify passes then the the user's data is stored in req.user and the endpoint for that route has access to req.user and can use the authenticated in user's data:

```js
// auth.js

const protect = async (req, res, next) => {
  let token;

  // check if the client sent the authorization attribute in the form of "Bearer <JWT>" in the request headers
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1]; // get the JWT

      const decoded = jwt.verify(token, process.env.JWT_SECRET); // get the payload from the JWT (holds user id)

      // store the user data for that user id inside of req.user
      req.user = await prisma.user.findUnique({
        where: {
          id: decoded.id,
        },
        select: {
          id: true,
          username: true,
          email: true,
          // if you wanted to know if the role of the user then you would include (in the DB it would be admin, manager, or user):
          // role: true
        },
      });

      next();
    } catch (e) {
      console.error(e);

      const err = new Error("Unauthorized");
      err.status = 401;
      next(err);
    }
  }
  if (!token) {
    const err = new Error(
      "Request is missing required authentication credential."
    );
    err.status = 401;
    next(err);
  }
};
```

To use this, we go into a route file and pass the protect middleware to the routes that are private:

```js
// userRoutes.js

userRouter.get("/me", protect, userController.asyncGetUserData);
```

We can use the authenticated user's data inside the protected route endpoint. When the client hits that route they'll get back there information as a response:

```js
// userRoutes.js

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
```

For our posts CRUD API, we only want users to CRUD their own posts. When a user logs in, we authenticate them via the protect middleware, then inside each endpoint we can access the authenticated user by using req.user. We can modify the DB logic and instead of making a query for all posts, etc we query for the user specific posts using req.user.id:

```js
// postsController.js

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
        created_by: req.user.id, // use the created_by foregin key with req.user.id to query for only the authenticated user's posts
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

    // if the post exists, make sure the post was created by the authenticated user
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
```

Now, when a request is made to an endpoint, it will CRUD that authenticated user's posts only even though the DB post table holds all posts from
every user. So we use req.user on the server whenever we are handling user specfic operations.

## Forgot password System

To add in a forgotten password system we go through this flow:

User clicks a "Forgot Password" link and enters their email address. The client makes a POST request to the server with the email in the request body. The server verifies that email is in the DB, generates a password reset token. A password reset token is just random bytes added on to a link that is sent to the user's email such as: `https://your-app.com/reset-password?token=<reset_token>`. When the user clicks the link and enters their new password, the server will extract the token from the URL and the password from the request body. The server can compare the token extract to the token that is saved to the user in the DB. If they match then its verfied and the server will update the password. If they dont match then we assume the client just entered random bytes that wasn't sent by the server and wont allow a password change.

First, we need to update our User model and add in the fields: passwordResetToken and passwordResetTokenExpiry:

```prisma
model User {
  id                     Int      @id @default(autoincrement())
  email                  String   @unique
  username               String   @db.VarChar(30) @unique
  password               String
  passwordResetToken     String?  // Nullable reset token
  passwordResetTokenExpiry DateTime? // Nullable expiration time

  posts     Post[]
}
```

Next, we need to create new POST endpoints for the forgot password and password reset:

```js
// userRoutes.js

userRouter.post("/forgot-password", userController.asyncForgotPassword);
userRouter.post("/forgot-password/:token", userController.asyncResetPassword);
```

Next, we add the forgot password endpoint controller logic:

```js
// userController.js
import crypto from "crypto"; // install crytpo using: npm i crypto
import sendEmail from "../utils/sendEmail.js"; // install nodemailer using: npm i nodemailer

export const asyncForgotPassword = (req, res, next) => {
  const { email } = req.body;

  try {
    // Find the user
    const user = await prisma.user.findUnique({
      where: {
        email
      }
    });

    if (!user) {
      const err = new Error("Couldn't find your account.");
      err.status = 404;
      return next(err);
    }

    // Generate a token and set it expiry
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 1000 * 60 * 10); // token valid for 10 minutes (1000 * 60 * 10 is how many miliseconds are in 10 minutes)

    // Update user with the reset token
    await prisma.user.update({
      where: {
        email
      },
      data: {
        passwordResetToken: resetToken,
        passwordResetTokenExpiry: resetTokenExpiry,
      }
    });

    // Create reset link
    const resetLink = `${req.protocol}://${req.get("host")}/api/v1/users/reset-password/${resetToken}`;

    // Send email with reset link
    await asyncSendEmail({
      to: email,
      subject: "Password reset",
      text: `Password reset link: ${resetLink}`,
    });
  } catch (e) {
    console.error(e);
  }

  res.status(200).json({ msg: "Password reset link sent to your email." })
};
```

Next, we need to create the email-sending utility using nodemailer inside the utils directory:

```js
// sendEmail.js
import nodemailer from "nodemailer";

const asyncSendEmail = async ({ to, subject, text }) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const result = await transporter.sendMail({
    from: process.env.EMAIL_USERNAME,
    to,
    subject,
    text,
  });

  console.log(JSON.stringify(result, null, 4));
};

export default asyncSendEmail;
```

Next, we need to setup the environment variables:

In order for nodemailer to work with gmail you have to confirm you're a real person:

1. Go to your google account: https://myaccount.google.com/

2. Go to Security

3. Choose 2-Step Verfication and set it up

4. Go to: https://myaccount.google.com/apppasswords to create your app

5. Put a name to your app and create it.

6. A modal dialog will appear with your password and put that password into the EMAIL_PASSWORD env variable.

7. The EMAIL_USER is the email you set the password up for because thats the email that will send the email.

```.env
EMAIL_USERNAME="<the-email-you-want-to-send-from>"
EMAIL_PASSWORD="<16-bit-password-generated-by-gmail>"
```

Next, we need to setup the reset password controller logic:

```js
// userController.js

export const asyncResetPassword = async (req, res, next) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    // Find user with the token
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: token,
        passwordResetTokenExpiry: {
          gte: new Date(); // check if token is still valid by checking if the expiry time is greater than or equal to the current time, if so then its still valid (if token expires at 10:30 and its current 10:20 then the expiry time is still greater than current time so token is still valid)
        }
      }
    });

    if (!user) {
      const err = new Error("Invalid or expired token.");
      err.status = 400;
      return next(err);
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update the user's password and clear the reset token
    await prisma.user.update({
      where: {
        id: user.id
      },
      data: {
        password: hashPassword,
        passwordResetToken: null,
        passwordResetTokenExpiry: null,
      }
    });

    res.status(200).json({ msg: "Password has been reset sucessfully." });
  }
  catch (e) {
    console.error(e);
  }
}
```

## Summary

1. Create user endpoints

```js
// User endpoints
userRouter.post("/", userController.asyncRegisterUser);
userRouter.post("/login", userController.asyncLoginUser);
userRouter.get("/me", protect, userController.asyncGetUserData);
```

2. Create protected route middleware

```js
// auth.js

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.user = await prisma.user.findUnique({
        where: {
          id: decoded.id,
        },
        select: {
          id: true,
          username: true,
          email: true,
        },
      });

      next();
    } catch (e) {
      console.error(e);

      const err = new Error("Unauthorized");
      err.status = 401;
      next(err);
    }
  }
  if (!token) {
    const err = new Error(
      "Request is missing required authentication credential."
    );
    err.status = 401;
    next(err);
  }
};
```

3. Add auth logic to user endpoints:

```js
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

const generateJWT = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};
```

In the next module we'll add frontend integration using React.
