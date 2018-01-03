<?php

namespace nolbertovilchez\yii2;

use yii\base\Component;
use Adldap\Adldap;

class Ldap extends Component {

    public $options     = [];
    public $enableLogin = false;
    protected $_default = [
        'domain_controllers'   => [],
        'timeout'              => 5,
        'version'              => 3,
        'port'                 => 389,
        'base_dn'              => '',
        'use_ssl'              => false,
        'use_tls'              => false,
        'follow_referrals'     => false,
        'account_prefix'       => null,
        'account_suffix'       => null,
        'admin_username'       => '',
        'admin_password'       => '',
        'admin_account_prefix' => null,
        'admin_account_suffix' => null,
        'custom_options'       => [],
    ];
    private $_options   = [];
    private $_conn;

    public function init() {
        $this->_options = array_merge($this->_default, $this->options);

        $ad = new Adldap();
        $ad->addProvider($this->_options);

        $this->_conn = $ad->connect();
        parent::init();
    }

    public function validateLogin() {
        return $this->enableLogin;
    }

    public function authenticated($username, $password) {
        return $this->_conn->auth()->attempt($username, $password);
    }

    public function search($username) {
        return $this->_conn->user()->find($username);
    }

}
