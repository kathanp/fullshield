declare module 'mongoose' {
  export class Schema {
    constructor(definition: object);
  }
  export interface Model<T = unknown> {
    find(filter?: object): Promise<T[]>;
    findOne(filter?: object): Promise<T | null>;
  }
  export function model<T = unknown>(name: string, schema?: Schema): Model<T>;
  namespace mongoose {
    export { Schema, model };
  }
  export default mongoose;
}
