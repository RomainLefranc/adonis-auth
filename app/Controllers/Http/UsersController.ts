import type { HttpContextContract } from "@ioc:Adonis/Core/HttpContext";
import RegisterUserValidator from "App/Validators/RegisterUserValidator";
import LoginUserValidator from "App/Validators/LoginUserValidator";
import User from "App/Models/User";
import Hash from "@ioc:Adonis/Core/Hash";
import ResetPasswordUserValidator from "App/Validators/ResetPasswordUserValidator";
import ForgotPasswordUserValidator from "App/Validators/ForgotPasswordUserValidator";
import ResetPasswordToken from "App/Models/ResetPasswordToken";
import crypto from "crypto";
import { DateTime } from "luxon";

export default class UsersController {
  public async register({ request, response }: HttpContextContract) {
    const payload = await request.validate(RegisterUserValidator);

    const user = await User.create(payload);

    return {
      user,
    };
  }

  public async login({ auth, request, response }: HttpContextContract) {
    const payload = await request.validate(LoginUserValidator);

    const { email, password } = payload;

    const user = await User.query().where("email", email).first();

    if (!user) {
      return response.unauthorized("Email or password invalid");
    }

    if (!user.isVerified) {
      return response.unauthorized("User is not verified");
    }

    if (!(await Hash.verify(user.password, password))) {
      return response.unauthorized("Email or password invalid");
    }

    const token = await auth.use("api").generate(user);
    return token;
  }

  public async verify({ params, response }: HttpContextContract) {
    const verificationToken = params.verificationToken;

    const user = await User.query()
      .where("verificationToken", verificationToken)
      .first();

    if (!user) {
      return response.unauthorized("Verification token invalid");
    }

    user.isVerified = true;
    user.save();

    return {
      isVerified: user.isVerified,
    };
  }

  public async logout({ auth, response }: HttpContextContract) {
    await auth.use("api").revoke();
    return {
      revoked: true,
    };
  }

  public async resetPassword({
    params,
    request,
    response,
  }: HttpContextContract) {
    const payload = await request.validate(ResetPasswordUserValidator);
    const resetPasswordToken = params.resetPasswordToken;

    const { password } = payload;

    const user = await User.query()
      .whereHas("resetPasswordTokens", (query) => {
        query
          .where("reset_password_token", "=", resetPasswordToken)
          .andWhere("expires_at", ">=", DateTime.now().toSQL()!);
      })
      .preload("resetPasswordTokens")
      .first();

    if (!user) {
      return response.unauthorized("Reset password token expired or invalid");
    }

    user.password = password;
    user.save();

    await user.resetPasswordTokens[0].delete();
    return response.accepted("Password have been updated");
  }

  public async forgotPassword({ response, request }: HttpContextContract) {
    const payload = await request.validate(ForgotPasswordUserValidator);
    const { email } = payload;

    const user = await User.query().where("email", email).first();

    if (!user) {
      return response.accepted(
        "If a user with this email is registered, you will receive a password recovery email"
      );
    }

    if (!user.isVerified) {
      return response.unauthorized("User is not verified");
    }

    const ValidTokens = await ResetPasswordToken.query()
      .where("expires_at", ">=", DateTime.now().toSQL()!)
      .andWhere("user_id", user.id);

    if (ValidTokens.length == 0) {
      const EXPIRATION_DELAY = 2;
      const expirationDate = DateTime.now().plus({ hour: EXPIRATION_DELAY });

      const token = crypto.randomBytes(64).toString("hex");

      await ResetPasswordToken.create({
        resetPasswordToken: token,
        userId: user.id,
        expiresAt: expirationDate,
      });
    }
    return response.accepted(
      "If a user with this email is registered, you will receive a password recovery email"
    );
  }
}
