import { PrismaClient } from "@prisma/client";
import {
  USERS,
  USER_PREFERENCES,
  PRODUCTS,
  ORDERS,
  ORDER_ITEMS,
} from "./mock.js";

const prisma = new PrismaClient();

async function main() {
  await prisma.$queryRaw`TRUNCATE TABLE "public"."_ProductToUser" RESTART IDENTITY CASCADE;`;
  // 기존 데이터 삭제
  await prisma.orderItem.deleteMany();
  await prisma.order.deleteMany();
  await prisma.userPreference.deleteMany();
  await prisma.user.deleteMany();
  await prisma.product.deleteMany();

  // 목 데이터 삽입
  await prisma.product.createMany({
    data: PRODUCTS,
    skipDuplicates: true,
  });

  // `savedProducts` 필드를 제외하고 사용자 생성
  for (const user of USERS) {
    const { savedProducts, ...userData } = user; // eslint-disable-line no-unused-vars
    await prisma.user.create({ data: userData });
  }

  // `savedProducts` 관계 설정
  for (const user of USERS) {
    if (user.savedProducts) {
      await prisma.user.update({
        where: { id: user.id },
        data: { savedProducts: user.savedProducts },
      });
    }
  }

  await prisma.userPreference.createMany({
    data: USER_PREFERENCES,
    skipDuplicates: true,
  });

  await prisma.order.createMany({
    data: ORDERS,
    skipDuplicates: true,
  });

  await prisma.orderItem.createMany({
    data: ORDER_ITEMS,
    skipDuplicates: true,
  });
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
