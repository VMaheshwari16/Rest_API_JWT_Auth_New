<?php

class AuthController {

    public static function register($req) {

        if (empty($req['name']) || empty($req['email']) || empty($req['password'])) {
            Response::json("All fields are required", 422);
        }

        Validator::email($req['email']);
        Validator::password($req['password']);

        if (User::findByEmail($req['email'])) {
            Response::json("Email already exists", 409);
        }

        User::create([
            $req['name'],
            $req['email'],
            password_hash($req['password'], PASSWORD_DEFAULT)
        ]);

        Response::json("User registered successfully", 201);
    }

public static function login($req) {

    $user = User::findByEmail($req['email']);

    if (!$user || !password_verify($req['password'], $user['password'])) {
        Response::json("Invalid credentials", 401);
    }

    $accessToken = JWT::generate([
        "id" => $user['id'],
        "email" => $user['email']
    ]);

    $refreshToken = JWT::refreshToken();

    User::saveRefreshToken(
        $user['id'],
        $refreshToken,
        time() + (7 * 24 * 60 * 60)
    );

    setcookie(
        "refresh_token",
        $refreshToken,
        time() + (7 * 24 * 60 * 60),
        "/",
        "",
        false,   
        true     
    );

    Response::json([
        "access_token" => $accessToken
    ]);
}
public static function refresh() {

    if (!isset($_COOKIE['refresh_token'])) {
        Response::json("Unauthorized", 401);
    }

    $refreshToken = $_COOKIE['refresh_token'];

    $record = User::getRefreshToken($refreshToken);

    if (!$record || $record['expires_at'] < time()) {
        Response::json("Invalid refresh token", 401);
    }

    User::deleteRefreshToken($refreshToken);

    $newAccess = JWT::generate([
        "id" => $record['user_id']
    ]);

    $newRefresh = JWT::refreshToken();

    User::saveRefreshToken(
        $record['user_id'],
        $newRefresh,
        time() + (7 * 24 * 60 * 60)
    );

    setcookie(
        "refresh_token",
        $newRefresh,
        time() + (7 * 24 * 60 * 60),
        "/",
        "",
        false,
        true
    );

    Response::json([
        "access_token" => $newAccess
    ]);
}
}
