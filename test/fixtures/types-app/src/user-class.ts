const mongoose = require('mongoose');

class Bucket {
  find(filter: object): object {
    return filter;
  }
}

const items = new Bucket();

export function search(req: { query: { n: string } }): unknown {
  void mongoose;
  return items.find({ name: req.query.n });
}
