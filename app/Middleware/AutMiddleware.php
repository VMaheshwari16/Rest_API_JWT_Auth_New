<?php
class AuthMiddleware {
    public static function handle() {
        $headers = getallheaders();
        if (!isset($headers['Authorization'])) {
            Response::json(["error" => "Unauthorized"], 401);
        }

        $token = str_replace("Bearer ", "", $headers['Authorization']);
        $user = JWT::verify($token);

        if (!$user) {
            Response::json(["error" => "Invalid Token"], 401);
        }
        return $user;
    }
}
