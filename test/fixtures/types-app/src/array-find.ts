const mongoose = require('mongoose');

const items: Array<{ name: string }> = [];

export function search(req: { query: { n: string } }): unknown {
  void mongoose;
  return items.find({ name: req.query.n });
}
