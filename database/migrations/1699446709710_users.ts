import BaseSchema from "@ioc:Adonis/Lucid/Schema";
import crypto from "crypto";

export default class extends BaseSchema {
  protected tableName = "users";

  public async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.increments("id").primary();
      table.string("email", 255).notNullable().unique();
      table.string("password", 180).nullable();
      table.string("remember_me_token").nullable();
      table.boolean("is_email_verified").notNullable().defaultTo(false);
      table
        .string("verification_token", 180)
        .nullable()
        .defaultTo(crypto.randomBytes(64).toString("hex"));
      table
        .timestamp("created_at", { useTz: true })
        .notNullable()
        .defaultTo(this.now());
      table
        .timestamp("updated_at", { useTz: true })
        .notNullable()
        .defaultTo(this.now());
    });
  }

  public async down() {
    this.schema.dropTable(this.tableName);
  }
}
