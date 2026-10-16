import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Controller('items')
@UseGuards(AuthGuard('jwt'))
export class ItemsController {
  @Get()
  list(@Query('q') q: string) {
    return db.query('SELECT * FROM items WHERE name = $1', [String(q)]);
  }

  @Post()
  create(@Body() body: { q: string }) {
    return db.query('SELECT * FROM items WHERE name = $1', [String(body.q)]);
  }
}
