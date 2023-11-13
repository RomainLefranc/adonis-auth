import type { HttpContextContract } from "@ioc:Adonis/Core/HttpContext";
import RegisterUserValidator from "App/Validators/RegisterUserValidator";
import LoginUserValidator from "App/Validators/LoginUserValidator";
import User from "App/Models/User";
import Hash from "@ioc:Adonis/Core/Hash";
import ResetPasswordUserValidator from "App/Validators/ResetPasswordUserValidator";
import ForgotPasswordUserValidator from "App/Validators/ForgotPasswordUserValidator";
import Token from "App/Models/Token";
import crypto from "crypto";
import { DateTime } from "luxon";
import Mail from "@ioc:Adonis/Addons/Mail";
import Env from "@ioc:Adonis/Core/Env";

export default class UsersController {
  public async register({ request, response }: HttpContextContract) {
    const payload = await request.validate(RegisterUserValidator);

    const user = await User.create(payload);

    user.related("tokens").create({
      token: crypto.randomBytes(64).toString("hex"),
      type: "EMAIL_VERIFICATION",
    });

    await Mail.use("smtp").sendLater(
      (message) => {
        message.subject("Verify your account!");
        message.to(user.email);
      },
      {
        oTags: ["signup"],
      }
    );

    return response.ok(user);
  }

  public async login({ auth, request, response }: HttpContextContract) {
    const payload = await request.validate(LoginUserValidator);

    const { email, password } = payload;

    const user = await User.query().where("email", email).first();

    if (!user) return response.unauthorized("Email or password invalid");

    if (!user.isEmailVerified) return response.unauthorized("User is not verified");

    if (!(await Hash.verify(user.password, password))) return response.unauthorized("Email or password invalid");

    const oat = await auth.use("api").generate(user, { expiresIn: "7days" });

    response.cookie(String(Env.get("API_TOKEN_COOKIE_NAME")), oat.token, { maxAge: 60 * 60 * 24 * 7, sameSite: "none", secure: true, httpOnly: true });

    return response.ok(user);
  }

  public async verify({ params, response }: HttpContextContract) {
    const { verificationToken } = params;

    const token = await Token.query().preload("user").where("token", verificationToken).andWhere("type", "EMAIL_VERIFICATION").first();

    if (!token) return response.unauthorized("Verification token invalid");

    token.user.isEmailVerified = true;
    await token.user.save();
    await token.delete();

    return response.accepted("User is now verified");
  }

  public async logout({ auth, response }: HttpContextContract) {
    await auth.use("api").revoke();

    response.cookie(String(Env.get("API_TOKEN_COOKIE_NAME")), "", { maxAge: 0, sameSite: "none", secure: true, httpOnly: true });

    return response.accepted("User is now disconnected");
  }

  public async resetPassword({ params, request, response }: HttpContextContract) {
    const payload = await request.validate(ResetPasswordUserValidator);
    const { resetPasswordToken } = params;

    const { password } = payload;

    const token = await Token.query().preload("user").where("token", resetPasswordToken).andWhere("expires_at", ">=", DateTime.now().toSQL()!).first();

    if (!token) return response.unauthorized("Reset password token expired or invalid");

    token.user.password = password;
    await token.user.save();
    await token.delete();

    return response.accepted("Password have been updated");
  }

  public async forgotPassword({ response, request }: HttpContextContract) {
    const payload = await request.validate(ForgotPasswordUserValidator);
    const { email } = payload;

    const user = await User.query().where("email", email).first();

    if (!user) return response.accepted("If a user with this email is registered, you will receive a password recovery email");

    if (!user.isEmailVerified) return response.unauthorized("User is not verified");

    const ValidResetPasswordTokens = await Token.query().where("expires_at", ">=", DateTime.now().toSQL()!).andWhere("user_id", user.id).andWhere("type", "PASSWORD_RESET");

    if (ValidResetPasswordTokens.length == 0) {
      const EXPIRATION_DELAY = 2;
      await user.related("tokens").create({
        token: crypto.randomBytes(64).toString("hex"),
        expiresAt: DateTime.now().plus({ hour: EXPIRATION_DELAY }),
        type: "PASSWORD_RESET",
      });

      await Mail.use("smtp").sendLater(
        (message) => {
          message.subject("Reset your pasword!");
          message.to(user.email);
        },
        {
          oTags: ["signup"],
        }
      );
    }
    return response.accepted("If a user with this email is registered, you will receive a password recovery email");
  }

  public async providerRedirect({ ally, auth, params, response }: HttpContextContract) {
    const { providerName } = params;

    if (await auth.check()) return response.notAcceptable();

    return response.send(await ally.use(providerName).stateless().redirectUrl());
  }

  public async providerCallback({ auth, ally, params, response }: HttpContextContract) {
    const { providerName } = params;

    if (await auth.check()) return response.notAcceptable();

    const provider = ally.use(providerName).stateless();

    if (provider.accessDenied()) return "Access was denied";

    if (provider.hasError()) return provider.getError();

    const { token } = await provider.accessToken();
    const providerUser = await provider.userFromToken(token);

    let user = await User.query()
      .where("email", providerUser.email!)
      .orWhereHas("socials", (query) => {
        query.where("provider", providerName).andWhere("provider_id", providerUser.id);
      })
      .first();

    if (!user) {
      user = await User.create({
        email: providerUser.email!,
      });
    }

    await user.related("socials").firstOrCreate({
      provider: providerName,
      providerId: providerUser.id,
    });

    const oat = await auth.use("api").generate(user, { expiresIn: "7days" });

    response.cookie(String(Env.get("API_TOKEN_COOKIE_NAME")), oat.token, { maxAge: 60 * 60 * 24 * 7, sameSite: "none", secure: true, httpOnly: true });

    return response.ok(user);
  }
}
