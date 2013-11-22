<?php

/**
 * @author Petr Besir Horacek <sirbesir@gmail.com>
 */

namespace Security;

use \Nette\Security\Permission;

class Acl extends \Nette\Security\Permission
{

    public function __construct()
    {
        //role
        $this->addRole('guest');
        $this->addRole('admin');

        //zdroje
        $this->addResource('Front:Sign');
        $this->addResource('Front:Homepage');

        //privilegia
        $this->allow('user', 'Front:Homepage',  array('view','default'));
        $this->allow('admin',  Permission::ALL, Permission::ALL);
    }

}