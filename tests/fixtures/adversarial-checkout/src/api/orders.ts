import { Router } from "express";

import { requireSession } from "../middleware/session";
import { getOrder, updateOrder, listOrdersForCustomer } from "../store/orders";

export const router = Router();

// Reads are behind the session middleware and scoped to the caller.
router.get("/orders", requireSession, async (req, res) => {
  const orders = await listOrdersForCustomer(req.session.customerId);
  res.json({ orders });
});

router.get("/orders/:id", requireSession, async (req, res) => {
  const order = await getOrder(req.params.id);
  if (!order || order.customerId !== req.session.customerId) {
    return res.status(404).json({ error: "not_found" });
  }
  res.json(order);
});

// Written before the session middleware landed. Never revisited: no
// authentication, and no check that the caller owns the order.
router.post("/orders/:id", async (req, res) => {
  const order = await updateOrder(req.params.id, req.body);
  res.json(order);
});
