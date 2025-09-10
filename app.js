import cors from "cors";
import * as dotenv from "dotenv";
dotenv.config();
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import express from "express";
import { PrismaClient, Prisma } from "@prisma/client";
import { assert } from "superstruct";
import {
  CreateUser,
  PatchUser,
  Login,
  CreateProduct,
  PatchProduct,
  CreateOrder,
  PatchOrder,
  PostSavedProduct,
} from "./structs.js";

const prisma = new PrismaClient();

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());

function asyncHandler(handler) {
  return async function (req, res, next) {
    try {
      await handler(req, res, next);
    } catch (e) {
      if (
        e.name === "StructError" ||
        e instanceof Prisma.PrismaClientValidationError
      ) {
        res.status(400).send({ message: e.message });
      } else if (
        e instanceof Prisma.PrismaClientKnownRequestError &&
        e.code === "P2025"
      ) {
        res.sendStatus(404);
      } else if (e.name === "AuthError") {
        res.status(401).send({ message: e.message || "Authentication failed" });
      } else {
        // 예상치 못한 에러는 next를 통해 Express의 기본 에러 핸들러로 전달합니다.
        next(e);
      }
    }
  };
}

class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthError";
  }
}

const auth = asyncHandler(async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    throw new AuthError("No token provided");
  }

  const decoded = Buffer.from(token, "base64").toString("ascii");
  const [userId, password] = decoded.split(":");

  if (!userId || !password) {
    throw new AuthError("Invalid token format");
  }

  const user = await prisma.user.findUniqueOrThrow({
    where: { id: userId },
    include: {
      userPreference: true,
    },
  });

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw new AuthError("Invalid credentials in token");
  }

  req.user = user;
  next();
});

/*********** auth ***********/

app.post(
  "/auth/login",
  asyncHandler(async (req, res) => {
    assert(req.body, Login);
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new AuthError("Invalid credentials");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new AuthError("Invalid credentials");
    }

    const token = Buffer.from(`${user.id}:${password}`).toString("base64");

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      // 1일 후 만료 (24시간 * 60분 * 60초 * 1000밀리초)
      maxAge: 24 * 60 * 60 * 1000,
      secure: process.env.NODE_ENV === "production", // HTTPS에서만 쿠키 전송
    });

    res.status(200).send({ message: "Logged in successfully" });
  })
);

app.post(
  "/auth/logout",
  asyncHandler(async (req, res) => {
    res.clearCookie("token");
    res.status(200).send({ message: "Logged out successfully" });
  })
);

app.get(
  "/users/me",
  auth,
  asyncHandler(async (req, res) => {
    // auth 미들웨어에서 req.user에 저장한 사용자 정보를 반환합니다.
    res.send(req.user);
  })
);

/*********** users ***********/

app.get(
  "/users",
  asyncHandler(async (req, res) => {
    const { offset = 0, limit = 10, order = "newest" } = req.query;
    let orderBy;
    switch (order) {
      case "oldest":
        orderBy = { createdAt: "asc" };
        break;
      case "newest":
      default:
        orderBy = { createdAt: "desc" };
    }
    const users = await prisma.user.findMany({
      orderBy,
      skip: parseInt(offset),
      take: parseInt(limit),
      include: {
        userPreference: {
          select: {
            receiveEmail: true,
          },
        },
      },
    });
    res.send(users);
  })
);

app.get(
  "/users/:id",
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const user = await prisma.user.findUniqueOrThrow({
      where: { id },
      include: {
        userPreference: true,
      },
    });
    res.send(user);
  })
);

app.post(
  "/users",
  asyncHandler(async (req, res) => {
    assert(req.body, CreateUser);
    const { userPreference, ...userFields } = req.body;
    const hashedPassword = await bcrypt.hash(userFields.password, 10);
    userFields.password = hashedPassword;
    const user = await prisma.user.create({
      data: {
        ...userFields,
        userPreference: {
          create: userPreference,
        },
      },
      include: {
        userPreference: true,
      },
    });
    res.status(201).send(user);
  })
);

app.patch(
  "/users/:id",
  asyncHandler(async (req, res) => {
    assert(req.body, PatchUser);
    const { id } = req.params;
    const { userPreference, ...userFields } = req.body;
    if (userFields.password) {
      const hashedPassword = await bcrypt.hash(userFields.password, 10);
      userFields.password = hashedPassword;
    }
    const user = await prisma.user.update({
      where: { id },
      data: {
        ...userFields,
        userPreference: {
          update: userPreference,
        },
      },
      include: {
        userPreference: true,
      },
    });
    res.send(user);
  })
);

app.delete(
  "/users/:id",
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    await prisma.user.delete({
      where: { id },
    });
    res.sendStatus(204);
  })
);

// 다대다 관계 user의 savedProducts 조회
// 인증된 사용자 본인의 savedProducts만 조회 가능
app.get(
  "/users/me/saved-products",
  auth,
  asyncHandler(async (req, res) => {
    const { id } = req.user;
    const { savedProducts } = await prisma.user.findUniqueOrThrow({
      where: { id },
      include: {
        savedProducts: true,
      },
    });
    res.send(savedProducts);
  })
);

// 다대다 관계 user의 savedProducts 생성/제거
// 인증된 사용자 본인의 savedProducts만 조작 가능
app.post(
  "/users/me/saved-products",
  auth,
  asyncHandler(async (req, res) => {
    assert(req.body, PostSavedProduct);
    const userId = req.user.id;
    const { productId } = req.body;
    const isProductSaved =
      (await prisma.user.count({
        where: {
          id: userId,
          savedProducts: {
            some: { id: productId },
          },
        },
      })) > 0;

    let savedProducts;

    if (isProductSaved) {
      const user = await prisma.user.update({
        where: { id: userId },
        data: {
          savedProducts: {
            disconnect: {
              id: productId,
            },
          },
        },
        include: {
          savedProducts: true,
        },
      });
      savedProducts = user.savedProducts;
      res.send(savedProducts);
    } else {
      const user = await prisma.user.update({
        where: { id: userId },
        data: {
          savedProducts: {
            connect: {
              id: productId,
            },
          },
        },
        include: {
          savedProducts: true,
        },
      });
      savedProducts = user.savedProducts;
      res.status(201).send(savedProducts);
    }
  })
);

app.get(
  "/users/:id/orders",
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { orders } = await prisma.user.findUniqueOrThrow({
      where: { id },
      include: {
        orders: true,
      },
    });
    res.send(orders);
  })
);

/*********** products ***********/

app.get(
  "/products",
  asyncHandler(async (req, res) => {
    const {
      offset = 0,
      limit = 10,
      order = "newest",
      category,
      search,
    } = req.query;
    let orderBy;
    switch (order) {
      case "priceLowest":
        orderBy = { price: "asc" };
        break;
      case "priceHighest":
        orderBy = { price: "desc" };
        break;
      case "oldest":
        orderBy = { createdAt: "asc" };
        break;
      case "newest":
      default:
        orderBy = { createdAt: "desc" };
    }
    const where = {
      ...(category ? { category } : {}),
      ...(search
        ? {
            name: {
              contains: search,
              mode: "insensitive", // 대소문자 구분 없이 검색
            },
          }
        : {}),
    };
    const products = await prisma.product.findMany({
      where,
      orderBy,
      skip: parseInt(offset),
      take: parseInt(limit),
    });
    res.send(products);
  })
);

app.get(
  "/products/:id",
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const product = await prisma.product.findUnique({
      where: { id },
    });
    res.send(product);
  })
);

app.post(
  "/products",
  asyncHandler(async (req, res) => {
    assert(req.body, CreateProduct);
    const product = await prisma.product.create({
      data: req.body,
    });
    res.status(201).send(product);
  })
);

app.patch(
  "/products/:id",
  asyncHandler(async (req, res) => {
    assert(req.body, PatchProduct);
    const { id } = req.params;
    const product = await prisma.product.update({
      where: { id },
      data: req.body,
    });
    res.send(product);
  })
);

app.delete(
  "/products/:id",
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    await prisma.product.delete({
      where: { id },
    });
    res.sendStatus(204);
  })
);

/*********** orders ***********/

app.get(
  "/orders",
  asyncHandler(async (req, res) => {
    const orders = await prisma.order.findMany();
    res.send(orders);
  })
);

app.get(
  "/orders/:id",
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const order = await prisma.order.findUniqueOrThrow({
      where: { id },
      include: {
        orderItems: true,
      },
    });
    let total = 0;
    order.orderItems.forEach((orderItem) => {
      total += orderItem.unitPrice * orderItem.quantity;
    });
    order.total = total;
    res.send(order);
  })
);

app.post(
  "/orders",
  asyncHandler(async (req, res) => {
    assert(req.body, CreateOrder);
    const { userId, orderItems } = req.body;

    const productIds = orderItems.map((orderItem) => orderItem.productId);
    const products = await prisma.product.findMany({
      where: { id: { in: productIds } },
    });

    function getQuantity(productId) {
      const orderItem = orderItems.find(
        (orderItem) => orderItem.productId === productId
      );
      return orderItem.quantity;
    }

    const isSufficientStock = products.every((product) => {
      const { id, stock } = product;
      return stock >= getQuantity(id);
    });

    if (!isSufficientStock) {
      throw new Error("Insufficient Stock");
    }

    // 주문 수량에 맞게 상품 재고 감소
    const queries = productIds.map((productId) =>
      prisma.product.update({
        where: { id: productId },
        data: {
          stock: {
            decrement: getQuantity(productId),
          },
        },
      })
    );

    // 상품 생성, 재고 감소 트랜젝션
    const [order] = await prisma.$transaction([
      prisma.order.create({
        data: {
          userId,
          orderItems: {
            create: orderItems,
          },
        },
        include: {
          orderItems: true,
        },
      }),
      ...queries,
    ]);

    res.status(201).send(order);
  })
);

app.patch(
  "/orders/:id",
  asyncHandler(async (req, res) => {
    assert(req.body, PatchOrder);
    const { id } = req.params;
    const order = await prisma.order.update({
      where: { id },
      data: req.body,
    });
    res.send(order);
  })
);

app.delete(
  "/orders/:id",
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    await prisma.order.delete({ where: { id } });
    res.sendStatus(204);
  })
);

app.listen(process.env.PORT || 3000, () => console.log("Server Started"));
