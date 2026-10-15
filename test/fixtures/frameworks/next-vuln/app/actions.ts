'use server';

export async function createItem(formData: FormData) {
  const name = formData.get('name');
  db.query('INSERT INTO items (name) VALUES (' + name + ')');
}
