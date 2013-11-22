<?php

namespace Security;

/**
 * SecurityHelpers
 * Petr Besir Horáček <sirbesir@gmail.com>
 */
final class Helpers
{
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
		return crypt($password, $salt ?: '$2a$07$' . \Nette\Utils\Strings::random(22));
	}
}