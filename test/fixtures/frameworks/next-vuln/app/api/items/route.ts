export async function GET(request: Request) {
  const body = await request.json();
  User.find(body);
  return Response.json(body);
}

export async function POST(request: Request) {
  const q = request.nextUrl.searchParams.get('q');
  db.query('SELECT * FROM items WHERE name = ' + q);
  return Response.json({ q });
}
