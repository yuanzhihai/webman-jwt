<?php

namespace yzh52521\Jwt;

use yzh52521\Jwt\Exception\JWTException;
use yzh52521\Jwt\User\AuthorizationUserInterface;

class User
{
    /**
     * @var AuthorizationUserInterface
     */
    protected $model;

    public function __construct($model)
    {
        $class = new $model;
        if ($class instanceof AuthorizationUserInterface) {
            $this->model = $class;
        } else {
            throw new JWTException( 'must be implements yzh52521\Jwt\User\AuthorizationUserInterface',500 );
        }
    }

    /**
     * 获取登录用户对象
     *
     * @param $uid
     * @return AuthorizationUserInterface
     */
    public function get($uid)
    {
        return $this->model->getUserById( $uid );
    }
}
