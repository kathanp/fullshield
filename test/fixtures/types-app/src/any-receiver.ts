const mongoose = require('mongoose');

export function search(items: any, req: { query: { n: string } }): unknown {
  void mongoose;
  return items.find({ name: req.query.n });
}
