function handler(req) {
  eval(scrub(req.body.code));
}
