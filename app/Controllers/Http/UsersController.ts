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
import Mail from "@ioc:Adonis/Addons/Mail";

export default class UsersController {
  public async register({ request, response }: HttpContextContract) {
    const payload = await request.validate(RegisterUserValidator);
    const user = await User.create(payload);

    await Mail.use("smtp").sendLater(
      (message) => {
        message.subject("Verify your account!");
        message.to(user.email);
      },
      {
        oTags: ["signup"],
      }
    );

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

    if (!user.isEmailVerified) {
      return response.unauthorized("User is not verified");
    }

    if (!(await Hash.verify(user.password, password))) {
      return response.unauthorized("Email or password invalid");
    }

    const token = await auth.use("api").generate(user);
    return token;
  }

  public async verify({ params, response }: HttpContextContract) {
    const { verificationToken } = params;

    const user = await User.query()
      .where("verificationToken", verificationToken)
      .first();

    if (!user) {
      return response.unauthorized("Verification token invalid");
    }

    user.isEmailVerified = true;
    user.verificationToken = null;
    await user.save();

    return response.accepted("User is now verified");
  }

  public async logout({ auth, response }: HttpContextContract) {
    await auth.use("api").revoke();
    return response.accepted("User is now disconnected");
  }

  public async resetPassword({
    params,
    request,
    response,
  }: HttpContextContract) {
    const payload = await request.validate(ResetPasswordUserValidator);
    const { resetPasswordToken } = params;

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

    if (!user.isEmailVerified) {
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
    return response.accepted(
      "If a user with this email is registered, you will receive a password recovery email"
    );
  }

  public async providerRedirect({ ally, params }: HttpContextContract) {
    const { providerName } = params;
    return ally.use(providerName).redirect();
  }

  public async providerCallback({ auth, ally, params }: HttpContextContract) {
    const { providerName } = params;

    const provider = ally.use(providerName);

    if (provider.accessDenied()) {
      return "Access was denied";
    }

    if (provider.stateMisMatch()) {
      return "Request expired. Retry again";
    }

    if (provider.hasError()) {
      return provider.getError();
    }

    const providerUser = await provider.user();

    let user = await User.query()
      .where("email", providerUser.email!)
      .orWhereHas("socials", (query) => {
        query
          .where("provider", providerName)
          .andWhere("provider_id", providerUser.id);
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

    const token = await auth.use("api").generate(user);
    return token;
  }
}
