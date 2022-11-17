<?php

namespace yzh52521\Jwt\Middleware;

use Webman\Http\Request;
use Webman\Http\Response;
use Webman\MiddlewareInterface;
use yzh52521\Jwt\Exception\TokenValidException;
use yzh52521\Jwt\JWT;
use yzh52521\Jwt\Util\JWTUtil;

class JWTAuthDefaultSceneMiddleware implements MiddlewareInterface
{
    protected $jwt;

    public function __construct(JWT $jwt)
    {
        $this->jwt = $jwt;
    }

    public function process(Request $request,callable $next): Response
    {
        $token = JWTUtil::getToken( $request );
        if ($token !== false && $this->jwt->verifyTokenAndScene( 'default',$token )) {
            return $next( $request );
        }

        throw new TokenValidException( 'Token authentication does not pass',400 );
    }
}