<?php

use Nette\Security;

/*
CREATE TABLE users (
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
	/** @var Nette\Database\Connection */
	private $database;

	public function __construct(Nette\Database\Connection $database)
	{
		/**
		 * @todo Reconsider the appliccation database and orm
		 */
		$this->database = $database;
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
		$row = $this->database->table('users')->where('username', $username)->fetch();

		if (!$row) {
			throw new Security\AuthenticationException('The username is incorrect.', self::IDENTITY_NOT_FOUND);
		}

		if ($row->password !== $this->calculateHash($password, $row->password)) {
			throw new Security\AuthenticationException('The password is incorrect.', self::INVALID_CREDENTIAL);
		}

		unset($row->password);
		return new Security\Identity($row->id, $row->role, $row->toArray());
	}

	/**
	 * Computes salted password hash.
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @param  string
	 * @return string
	 */
	public static function calculateHash($password, $salt = NULL)
	{
		if ($password === \Nette\Utils\Strings::upper($password)) { // perhaps caps lock is on
			$password = \Nette\Utils\Strings::lower($password);
		}
		return crypt($password, $salt ?: '$2a$07$' . \Nette\Utils\StringsStrings::random(22));
	}

}
