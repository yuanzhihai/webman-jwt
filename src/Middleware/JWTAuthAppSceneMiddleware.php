<?php

namespace yzh52521\Jwt\Middleware;

use Webman\Http\Request;
use Webman\Http\Response;
use Webman\MiddlewareInterface;
use yzh52521\Jwt\Exception\TokenValidException;
use yzh52521\Jwt\JWT;
use yzh52521\Jwt\Util\JWTUtil;

class JWTAuthAppSceneMiddleware implements MiddlewareInterface
{
    protected $jwt;

    public function __construct(JWT $jwt)
    {
        $this->jwt = $jwt;
    }

    public function process(Request $request,callable $next): Response
    {
        $token = JWTUtil::getToken( $request );
        if ($token !== false && $this->jwt->verifyTokenAndScene( 'app',$token )) {
            $jwtConfig = $this->jwt->getJwtSceneConfig();
            $jwtConfig['user_model'] && $request->user = $this->jwt->getUser();
            return $next( $request );
        }

        throw new TokenValidException( 'Token authentication does not pass',400 );
    }
}