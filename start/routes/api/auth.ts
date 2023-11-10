import Route from "@ioc:Adonis/Core/Route";

export default function authRoutes() {
  Route.group(() => {
    Route.post("/register", "UsersController.register").as("register");
    Route.get("/verify/:verificationToken", "UsersController.verify")
      .where("verificationToken", /^[a-z0-9_-]+$/)
      .as("verify");
    Route.post("/login", "UsersController.login").as("login");
    Route.post("/forgot-password", "UsersController.forgotPassword").as("forgotPasswword");
    Route.post("/reset-password/:resetPasswordToken", "UsersController.resetPassword")
      .where("resetPasswordToken", /^[a-z0-9_-]+$/)
      .as("resetPassword");
    Route.post("/logout", "UsersController.logout").middleware(["auth:api"]).as("logout");
    Route.get("/:providerName/redirect", "UsersController.providerRedirect")
      .where("providerName", /^[a-z]+$/)
      .as("redirect");
    Route.get("/:providerName/callback", "UsersController.providerCallback")
      .where("providerName", /^[a-z]+$/)
      .as("callback");
  })
    .prefix("/auth")
    .as("auth");
}
