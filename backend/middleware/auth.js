import jwt from "jsonwebtoken";
import prisma from "../config/prismaClient.js";

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

export default protect;
