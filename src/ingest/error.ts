/** Local ingest failed for one file. Other files are still read. */
export class IngestError extends Error {
  readonly code = 'FS-E012';
  readonly file: string;
  readonly schemaError: string;

  constructor(file: string, schemaError: string) {
    const prefix = file.length > 0 ? `${file}: ` : '';
    super(`${prefix}${schemaError} (FULLSHIELD_EXPERIMENTAL_INGEST)`);
    this.name = 'IngestError';
    this.file = file;
    this.schemaError = schemaError;
  }
}
