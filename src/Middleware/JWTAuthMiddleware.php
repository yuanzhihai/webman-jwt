<?php

namespace yzh52521\Jwt\Middleware;

use Webman\Http\Response;
use Webman\Http\Request;
use Webman\MiddlewareInterface;
use yzh52521\Jwt\Exception\TokenValidException;
use yzh52521\Jwt\JWT;
use yzh52521\Jwt\Util\JWTUtil;

class JWTAuthMiddleware implements MiddlewareInterface
{


    protected $jwt;

    public function __construct(JWT $jwt)
    {
        $this->jwt = $jwt;
    }

    public function process(Request $request,callable $next): Response
    {
        $token = JWTUtil::handleToken( $request );
        if ($token !== false && $this->jwt->verifyToken( $token )) {
            return $next( $request );
        }

        throw new TokenValidException( 'Token authentication does not pass',400 );
    }
}