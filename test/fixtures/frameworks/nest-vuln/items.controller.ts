import { Controller, Get, Post, Body, Query } from '@nestjs/common';

@Controller('items')
export class ItemsController {
  @Get()
  list(@Query() query: { q: string }) {
    return this.users.find(query);
  }

  @Post()
  create(@Body() body: { q: string }) {
    return db.query('SELECT * FROM items WHERE name = ' + body.q);
  }
}
