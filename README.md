# SimpleJWT
Json Web Token for PHP

## Installation

```bash
composer install acelan/simple-jwt
```

## Usage

```php
use AceLan\JsonWebToken;

$payload = array('sub' => 'example@gmail.com', 'infoData' => ['name' => 'David']);

$token = JWTAuthLibrary::getToken($payload);

print_r($token);

$getPayload = JWTAuthLibrary::verifyToken($token['accessToken']);

$getRrfreshPayload = JWTAuthLibrary::verifyRefreshToken($token['accessToken'], $token['refreshToken']);

echo "<br>";
var_dump($getPayload);
echo "<br>";
var_dump($getRrfreshPayload);
```