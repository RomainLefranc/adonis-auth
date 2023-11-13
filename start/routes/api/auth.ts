import Route from "@ioc:Adonis/Core/Route";

export default function authRoutes() {
  Route.group(() => {
    Route.post("/register", "UsersController.register")
      .middleware("throttle:register");

    Route.get("/verify/:verificationToken", "UsersController.verify")
      .where("verificationToken", /^[a-z0-9_-]+$/)
      .middleware("throttle:global");

    Route.post("/login", "UsersController.login")
      .middleware("throttle:login");

    Route.post("/forgot-password", "UsersController.forgotPassword")
      .middleware("throttle:global");

    Route.post("/reset-password/:resetPasswordToken", "UsersController.resetPassword")
      .where("resetPasswordToken", /^[a-z0-9_-]+$/)
      .middleware("throttle:global");

    Route.post("/logout", "UsersController.logout")
      .middleware(["auth:api"]);

    Route.get("/:providerName/redirect","UsersController.providerRedirect")
      .where("providerName", /^[a-z]+$/);

    Route.get("/:providerName/callback","UsersController.providerCallback")
      .where("providerName", /^[a-z]+$/);
  }).prefix("/auth");
}
