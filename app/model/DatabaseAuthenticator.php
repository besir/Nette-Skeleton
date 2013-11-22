<?php

use Nette\Security,
	Nette\Utils\Strings;


/*
CREATE TABLE user (
	id int(11) NOT NULL AUTO_INCREMENT,
	username varchar(50) NOT NULL,
	password char(60) NOT NULL,
	role varchar(20) NOT NULL,
	PRIMARY KEY (id)
);
*/

/**
 * Users authenticator.
 * @author Petr Besir Horacek <sirbesir@gmail.com>
 */
class DatabaseAuthenticator extends Nette\Object implements Security\IAuthenticator
{
	/** @var \Nette\Database\Connection */
	private $database;

	/**
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @param \Nette\Database\Connection $database
	 */
	public function __construct(\DibiConnection $database)
	{
		$this->injectDatabase($database);
	}

	/**
	 * Performs an authentication.
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @return Nette\Security\Identity
	 * @throws Nette\Security\AuthenticationException
	 */
	public function authenticate(array $credentials)
	{
		list($username, $password) = $credentials;
		$row = $this->getDatabase()->table('users')->where('username', $username)->fetch();

		if (!$row) {
			throw new Security\AuthenticationException('The username is incorrect.', self::IDENTITY_NOT_FOUND);
		}

		if ($row->password !== \Security\Helpers::calculateHash($password, $row->password)) {
			throw new Security\AuthenticationException('The password is incorrect.', self::INVALID_CREDENTIAL);
		}

		unset($row->password);
		return new Security\Identity($row->id, $row->role, $row->toArray());
	}

	// <editor-fold defaultstate="collapsed" desc="Dependency Injection">
	/**
	 * User service injection
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @param \Nette\Database\Connection $database
	 */
	public function injectDatabase(\Nette\Database\Connection $database)
	{
		if ($this->database !== NULL)
		{
			throw new \Nette\InvalidStateException('Database has already been set');
		}
		$this->database = $database;
	}
	// </editor-fold>

	/**
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @return \Nette\Database\Connection
	 */
	public function getDatabase()
	{
		return $this->database;
	}
}
