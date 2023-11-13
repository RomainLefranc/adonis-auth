import { DateTime } from "luxon";
import Hash from "@ioc:Adonis/Core/Hash";
import { column, beforeSave, BaseModel, hasMany, HasMany, hasOne, HasOne } from "@ioc:Adonis/Lucid/Orm";
import UserSocial from "./UserSocial";
import Token from "./Token";

export default class User extends BaseModel {
  @column({ isPrimary: true })
  public id: number;

  @column()
  public email: string;

  @column({ serializeAs: null })
  public password: string;

  @column()
  public rememberMeToken: string | null;

  @column()
  public isEmailVerified: boolean;

  @column()
  public verificationToken: string | null;

  @column.dateTime({ autoCreate: true })
  public createdAt: DateTime;

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  public updatedAt: DateTime;

  @hasMany(() => Token)
  public tokens: HasMany<typeof Token>;

  @hasMany(() => Token, { onQuery: (query) => query.where("type", "PASSWORD_RESET") })
  public resetPasswordTokens: HasMany<typeof Token>;

  @hasOne(() => Token, { onQuery: (query) => query.where("type", "EMAIL_VERIFICATION") })
  public emailVerificationToken: HasOne<typeof Token>;

  @hasMany(() => UserSocial)
  public socials: HasMany<typeof UserSocial>;

  @beforeSave()
  public static async hashPassword(user: User) {
    if (user.$dirty.password) {
      user.password = await Hash.make(user.password);
    }
  }
}
