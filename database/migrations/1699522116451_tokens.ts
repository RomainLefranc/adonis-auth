import BaseSchema from "@ioc:Adonis/Lucid/Schema";

export default class extends BaseSchema {
  protected tableName = "tokens";

  public async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.increments("id");
      table.integer("user_id").unsigned().references("id").inTable("users").onDelete("CASCADE");
      table.string("token", 180).notNullable();
      table.string("type").notNullable();
      table.timestamp("expires_at", { useTz: true }).nullable().defaultTo(null);
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(this.now());
    });
  }

  public async down() {
    this.schema.dropTable(this.tableName);
  }
}
