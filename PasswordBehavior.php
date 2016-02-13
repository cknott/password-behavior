<?php

/**
 * Class PasswordBehavior.php
 * Copyright 2016 Christian Knott <ck@cknott.net>
 */
class PasswordBehavior extends CActiveRecordBehavior
{

    public $passwordField = 'password';

    public function hashPassword()
    {
        /** @var CActiveRecord $owner */
        $owner = $this->getOwner();
        if(!is_a($owner, 'CActiveRecord')){
            throw new Exception('Only to be used with CActiveRecord instances');
        }
        $password = $owner->getAttribute($this->passwordField);

        $hash = '';
        if(function_exists('password_hash')){
            $hash = password_hash($password, PASSWORD_DEFAULT);
        } elseif(extension_loaded('mcrypt')){
            $salt = mcrypt_create_iv(22, MCRYPT_DEV_URANDOM);
            $salt = base64_encode($salt);
            $salt = str_replace('+', '.', $salt);
            $hash = crypt($password, '$2y$10$'.$salt.'$');
        }

        $owner->setAttribute($this->passwordField, $hash);
    }

}