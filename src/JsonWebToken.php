<?php

namespace AceLan\JsonWebToken;

date_default_timezone_set("Asia/Taipei");

class JsonWebToken
{

    /**
     * 使用HMAC資訊摘要時所使用的private key 這裡也可以實作RSA
     *
     * @var string
     */
    private static $key = 'EjLGRddgpaB7DcG2mVhEgmaiGL7bvUh1YYnSp7h9eop14QZmvvqptQXIUT0d6nA4'; //example key
    /**
     * header variable
     *
     * @var array
     */
    private static $header = array(
        'alg' => 'HS256', //signature的雜湊演算法
        'typ' => 'JWT'    //型態
    );
    /**
     * 發行者 variable
     *
     * @var string
     */
    private static $issName = 'jwt_admin';
    /**
     * accessTokenExpTime variable
     * 預設 2分鐘 (可自行設定 單位：秒數)
     *
     * @var integer
     */
    private static $accessTokenExpTime = 120;
    /**
     * refreshTokenExpTime variable
     * 預設4分鐘 (可自行設定 單位：秒數)
     *
     * @var integer
     */
    private static $refreshTokenExpTime = 240;

    /**
     * get JsonWebToken
     * @param array $payload jwt 格式如下 *必須
     * [
     *     'sub' => 'example@gmail.com',  //授權給哪位使用者
     *     'infoData' => [               //帶入內容
     *         'exampleName' => 'example',
     *         ...,
     *     ]
     * ]
     * @return bool|array ['access_token' => 'string', 'refresh_token'  => 'string']
     */
    public static function getToken(array $payload)
    {
        if (is_array($payload)) {
            $accessPayload = self::getProcessAccessPayload($payload);
            if (is_array($accessPayload) && isset($accessPayload['jti'])) {
                $refreshPayload = self::getProcessRefreshPayload($accessPayload['jti']);
                return array(
                    'accessToken' => self::getProcessAccessToken($accessPayload),
                    'refreshToken' => self::getProcessRefreshToken($refreshPayload),
                );
            }
        } else {
            return false;
        }
    }
    /**
     * Preprocess AccessPayload
     *
     * @param array array(
     *     'iss' => 'jwt_admin',                                   //(required)該JWT的簽發者
     *     'iat' => time(),                                        //(required)簽發時間
     *     'exp' => time() + self::$accessTokenExpTime,            //(required)過期時間
     *     'nbf' => time() + 3,                                    //(not required)該時間之前不接收處理該Token
     *     'sub' => $payload_info['sub'],                          //(required)面向的使用者
     *     'jti' => md5(uniqid('AccessTokenJWT'. time())),         //(required)該Token唯一標識
     *     'info_data' => $payload_info['info_data'] ?? array()    //(not required)使用者資料(不建議放入敏感資料如password)
     * );
     * @return @return bool|array ['access_token' => 'string', 'refresh_token'  => 'string']
     */
    private static function getProcessAccessPayload(array $payloadInfo)
    {
        if (is_array($payloadInfo)) {
            return array(
                'iss' => self::$issName,
                'iat' => time(),
                'exp' => time() + self::$accessTokenExpTime,
                'sub' => $payloadInfo['sub'],
                'jti' => md5(uniqid('AccessTokenJWT') . time()),
                'infoData' => $payloadInfo['infoData'] ?? array()
            );
        } else {
            return false;
        }
    }

    /**
     * Preprocess RefreshPayload
     * 加入accessTokenJti目的是來驗證RefreshToken跟AccessToken是同一組
     *
     * @param array $accessTokenJti
     * @return void
     */
    private static function getProcessRefreshPayload(string $accessTokenJti): array
    {
        return array(
            'iss' => self::$issName,
            'iat' => time(),
            'exp' => time() + self::$refreshTokenExpTime,
            'jti' => md5(uniqid('RefreshTokenJWT') . time()),
            'accessJti' => $accessTokenJti
        );
    }

    /**
     * processRefreshToken
     *
     * @param array $accessPayload
     * @return strting
     */
    private static function getProcessAccessToken(array $accessPayload): String
    {
        $base64AccessHeader = self::base64UrlEncode(json_encode(self::$header, JSON_UNESCAPED_UNICODE));
        $base64AccessPayload = self::base64UrlEncode(json_encode($accessPayload, JSON_UNESCAPED_UNICODE));
        $accessToken = $base64AccessHeader . '.' . $base64AccessPayload . '.' . self::signature(
            $base64AccessHeader . '.' . $base64AccessPayload,
            self::$key,
            self::$header['alg']
        );
        return $accessToken;
    }

    /**
     * processRefreshToken
     *
     * @param array $refreshPayload
     * @return strting
     */
    private static function getProcessRefreshToken(array $refreshPayload): String
    {
        $base64RefreshHeader = self::base64UrlEncode(json_encode(self::$header, JSON_UNESCAPED_UNICODE));
        $base64RefreshPayload = self::base64UrlEncode(json_encode($refreshPayload, JSON_UNESCAPED_UNICODE));
        $refreshToken = $base64RefreshHeader . '.' . $base64RefreshPayload . '.' . self::signature(
            $base64RefreshHeader . '.' . $base64RefreshPayload,
            self::$key,
            self::$header['alg']
        );
        return $refreshToken;
    }

    /**
     * 驗證token是否合法, 預設驗證exp,iat時間
     * @param string $Token 需要驗證的Accesstoken
     * @param string $showPayloadBool = false 是否顯示解密後資訊(略過簽發、過期時間驗證)
     * @return bool|array $payload
     */
    public static function verifyToken(string $Token, bool $showPayloadBool = false)
    {
        $tokens = explode('.', $Token);
        if (count($tokens) != 3) {
            return false;
        }
        list($base64header, $base64payload, $sign) = $tokens;

        //JWT演算法
        $base64decodeheader = json_decode(self::base64UrlDecode($base64header), JSON_OBJECT_AS_ARRAY);
        if (empty($base64decodeheader['alg'])) {
            return false;
        }
        //簽名驗證
        if (self::signature($base64header . '.' . $base64payload, self::$key, $base64decodeheader['alg']) !== $sign) {
            return false;
        }
        $payload = json_decode(self::base64UrlDecode($base64payload), JSON_OBJECT_AS_ARRAY);

        if (!$showPayloadBool) {
            //簽發時間大於當前伺服器時間驗證失敗
            if (isset($payload['iat']) && $payload['iat'] > time()) {
                return false;
            }
            //過期時間小於Server時間則驗證失敗
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                return false;
            }
        }

        return $payload;
    }

    /**
     * 驗證RefreshToken是否合法, 預設驗證exp,iat時間, RefreshToken合法且AccessToken已過期(略過檢查)
     * @param string $Token 需要驗證的RefreshToken
     * @return bool|array $payload
     */
    public static function verifyRefreshToken(string $accessToken, string $refreshToken, bool $showStatus = false)
    {
        if (is_array($refreshTokenPayload = self::verifyToken($refreshToken))) {
            $accessTokenPayload = self::verifyToken($accessToken, true);
            if ($refreshTokenPayload['accessJti'] === $accessTokenPayload['jti']) {
                return $showStatus ? true : $refreshTokenPayload;
            }
        } else {
            return false;
        }
    }

    /**
     * base64UrlEncode
     * @param string $input 需要base64_encode的字串
     * @return string
     */
    private static function base64UrlEncode(string $input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * base64UrlEncode
     * @param string $input 需要base64_decode的字串
     * @return bool|string
     */
    private static function base64UrlDecode(string $input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * HMAC SHA256簽名
     * hash_hmac document https://www.php.net/manual/zh/function.hash-hmac.php
     * @param string $input (要被雜湊的內容) 為base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key   private key
     * @param string $alg   Algorithm Preset SHA256
     * @return mixed
     */
    private static function signature(string $input, string $key, string $alg = 'HS256')
    {
        $alg_config = array(
            'HS256' => 'sha256'
        );
        return self::base64UrlEncode(hash_hmac($alg_config[$alg], $input, $key, true));
    }
}
