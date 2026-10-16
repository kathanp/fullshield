import { auth } from '../../../auth.js';

export async function GET(request: Request) {
  const session = await auth();
  if (!session) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const body = await request.json();
  const q = String(body.q);
  db.query('SELECT * FROM items WHERE name = $1', [q]);
  return Response.json({ q });
}
