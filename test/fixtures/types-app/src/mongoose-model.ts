import mongoose from 'mongoose';

const User = mongoose.model('User', new mongoose.Schema({ name: String }));

export function search(req: { query: { n: string } }): unknown {
  return User.find({ name: req.query.n });
}
