import { IsString } from 'class-validator';

const { MongoClient } = require('mongodb');

class UserDto {
  @IsString()
  name!: string;
}

app.post('/class', validate(UserDto), (req, res) => {
  collection.findOne({ name: req.body.name });
});
