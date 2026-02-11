<?php
class User {
    public static function create($data) {
        $db = Database::connect();
        $stmt = $db->prepare(
            "INSERT INTO users (name,email,password) VALUES (?,?,?)"
        );
        return $stmt->execute($data);
    }

    public static function findByEmail($email) {
        $db = Database::connect();
        $stmt = $db->prepare("SELECT * FROM users WHERE email=?");
        $stmt->execute([$email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public static function saveRefreshToken($userId, $token, $expiry) {

    $db = Database::connect();

    $stmt = $db->prepare(
        "INSERT INTO refresh_tokens (user_id, token, expires_at)
         VALUES (?, ?, ?)"
    );

    $stmt->execute([$userId, $token, $expiry]);
}


public static function getRefreshToken($token) {

    $db = Database::connect();

    $stmt = $db->prepare(
        "SELECT * FROM refresh_tokens WHERE token = ?"
    );

    $stmt->execute([$token]);

    return $stmt->fetch(PDO::FETCH_ASSOC);
}

public static function deleteRefreshToken($token) {

    $db = Database::connect();

    $stmt = $db->prepare(
        "DELETE FROM refresh_tokens WHERE token = ?"
    );

    $stmt->execute([$token]);
}

}
