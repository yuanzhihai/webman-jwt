<?php
declare( strict_types = 1 );

namespace yzh52521\Jwt\Util;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Validation\Validator;
use support\Request;

class JWTUtil
{
    /**
     * claims对象转换成数组
     *
     * @param $claims
     * @return mixed
     */
    public static function claimsToArray(DataSet $claims)
    {
        return $claims->all();
    }

    /**
     * 获取jwt token
     * @param Request $request
     * @return array
     */
    public static function getToken(Request $request)
    {
        $token = $request->header( 'Authorization' ) ?? '';
        $token = self::handleToken( $token );
        return $token;
    }

    /**
     * 解析token
     * @param Request $request
     * @return array
     */
    public static function getParserData(Request $request)
    {
        $token = $request->header( 'Authorization' ) ?? '';
        $token = self::handleToken( $token );
        return self::getParser()->parse( $token )->claims()->all();
    }

    /**
     * 处理token
     * @param string $token
     * @param string $prefix
     * @return bool|mixed|string
     */
    public static function handleToken(string $token,string $prefix = 'Bearer')
    {
        if (strlen( $token ) > 0) {
            $token = ucfirst( $token );
            $arr   = explode( "{$prefix} ",$token );
            $token = $arr[1] ?? '';
            if (strlen( $token ) > 0) {
                return $token;
            }
        }
        return false;
    }

    /**
     * @return Parser
     */
    public static function getParser(Decoder $decoder = null): Parser
    {
        if ($decoder == null) {
            return new Parser( new JoseEncoder() );
        }
        return new Parser( $decoder );
    }

    public static function getValidator(): Validator
    {
        return new Validator();
    }
}