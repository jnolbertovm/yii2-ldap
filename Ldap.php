<?php

namespace nolbertovilchez\yii2;

use yii\base\Component;

class Ldap extends Component {

    public $options     = [];
    public $enableLogin = false;
    protected $_default = [
        'server'         => '',
        'domain'         => '',
        'dc'             => '',
        'version'        => 3,
        'port'           => 389,
        'admin_username' => '',
        'admin_password' => '',
    ];
    private $_options   = [];
    private $_conn;

    public function init() {
        $this->_options = array_merge($this->_default, $this->options);

        $this->_conn = ldap_connect("ldaps://{$this->_options['server']}.{$this->_options['domain']}/", $this->_options['port']);
        ldap_set_option($this->_conn, LDAP_OPT_PROTOCOL_VERSION, $this->_options['version']);
        parent::init();
    }

    public function validateLogin() {
        return $this->enableLogin;
    }

    public function close() {
        ldap_close($this->_conn);
    }

    public function authenticated($username, $password) {
        $authenticated = ldap_bind($this->_conn, $username . "@" . $this->_options['domain'], $password);
        $this->close();
        return $authenticated;
    }

    public function search($username) {
        $filter  = "(samaccountname={$username})";
        $result  = ldap_search($this->_conn, $this->_options['dc'], $filter);
        $entries = ldap_get_entries($this->_conn, $result);
        $this->close();
        return $entries;
    }

    public function create($params) {
        $response['estado']  = true;
        $response['mensaje'] = "Usuario creado exitosamente";
        try {
            if (!isset($params['password'])) {
                throw new Exception("Password es requerido", 900);
            }
            if (!isset($params['username'])) {
                throw new Exception("Nombre de usuario es requerido", 900);
            }
            if (!isset($params['firstname'])) {
                throw new Exception("Nombres es requerido", 900);
            }
            if (!isset($params['lastname'])) {
                throw new Exception("Apellido Paterno es requerido", 900);
            }
            if (!isset($params['motherslastname'])) {
                throw new Exception("Apellido Materno es requerido", 900);
            }
            if (!isset($params['mail'])) {
                throw new Exception("Correo es requerido", 900);
            }
            if (!isset($params['phone'])) {
                throw new Exception("Telefono es requerido", 900);
            }
            if (!ldap_bind($this->_conn, $this->_options['admin_username'] . "@" . $this->_options['domain'], $this->_options['admin_password'])) {
                $error = "NRO: " . ldap_errno($this->_conn) . "<br/>DESCRIPCION: " . ldap_error($this->_conn) . "<br/>";
                throw new Exception("Error al autenticar al servidor - {$error}", 900);
            }

            $newPassword = '"' . $params['password'] . '"';
            $newPass     = iconv('UTF-8', 'UTF-16LE', $newPassword);

            $ldaprecord['cn']                 = "{$params['firstname']} {$params['lastname']} {$params['motherslastname']}";
            $ldaprecord['givenName']          = $params['firstname'];
            $ldaprecord['sn']                 = "{$params['lastname']} {$params['motherslastname']}";
            $ldaprecord['distinguishedname']  = "CN={$params['firstname']} {$params['lastname']} {$params['motherslastname']},CN=Users,{$this->_options['dc']}";
            $ldaprecord['instancetype']       = 4;
            $ldaprecord['displayname']        = "{$params['firstname']} {$params['lastname']} {$params['motherslastname']}";
            $ldaprecord['name']               = "{$params['firstname']} {$params['lastname']} {$params['motherslastname']}";
            $ldaprecord['objectclass'][0]     = "top";
            $ldaprecord['objectclass'][1]     = "person";
            $ldaprecord['objectclass'][2]     = "organizationalPerson";
            $ldaprecord['objectclass'][3]     = "user";
            $ldaprecord['mail']               = $params['mail'];
            $ldaprecord['telephoneNumber']    = $params['phone'];
            $ldaprecord["unicodepwd"]         = $newPass;
            $ldaprecord["sAMAccountName"]     = $params['username'];
            $ldaprecord["UserAccountControl"] = 512;

            $add = ldap_add($this->_conn, "cn={$params['firstname']} {$params['lastname']} {$params['motherslastname']},CN=Users,{$this->_options['dc']}", $ldaprecord);
            if (!$add) {
                $error = "NRO: " . ldap_errno($this->_conn) . "<br/>DESCRIPCION: " . ldap_error($this->_conn) . "<br/>";
                throw new Exception("Error al crear cuenta - {$error}", 900);
            }
        } catch (\Exception $ex) {
            $response['estado']  = false;
            $response['mensaje'] = $ex->getMessage();
        }

        $this->close();

        return $response;
    }

}
