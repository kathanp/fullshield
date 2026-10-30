function demo() {
  const app = {
    post(_path, handler) {
      handler({ body: { name: 'sample' } }, { send(value) { return value; } });
    },
  };
  const req = { body: { name: 'sample' } };
  const res = { send(value) { return value; } };
  // checklist: see rules/README.md
  app.post('/in', () => {
    res.send(req.body.name);
  });
}

demo();
