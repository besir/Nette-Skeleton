<?php

namespace Security;

/**
 * Authorizator service
 * @author Petr Besir Horáček <sirbesir@gmail.com>
 */
class AuthorizatorService extends \Nette\Object
{

	/** @var \Security\AuthorizatorDao $authorizatorDao */
	private $authorizatorDao;

	/**
	 * Construct
	 * @author Petr Besir Horáček <sirbesir@gmail.com>
	 * @param \Security\AuthorizatorDao $authorizatorDao
	 */
	public function __construct(\Security\AuthorizatorDao $authorizatorDao)
	{
		$this->injectAuthorizatorDao($authorizatorDao);
	}

	public function	getPrivileges()
	{
		return $this->getAuthorizatorDao()->getPrivileges();
	}

	public function getResources()
	{
		return $this->getAuthorizatorDao()->getResources();
	}

	public function getRoles()
	{
		return $this->getAuthorizatorDao()->getRoles();
	}

	public function getRules()
	{
		return $this->getAuthorizatorDao()->getRules();
	}

	// <editor-fold defaultstate="collapsed" desc="Dependency injection">
	/**
	 * Authorizator DAO injection
	 * @author Petr Besir Horáček <sirbesir@gmail.com>
	 * @param \Service\Authorizator $authorizatorDao
	 */
	private function injectAuthorizatorDao(\Security\AuthorizatorDao $authorizatorDao)
	{
		if ($this->authorizatorDao !== NULL)
		{
			throw new \Nette\InvalidStateException('Authorizator DAO has already been set');
		}
		$this->authorizatorDao = $authorizatorDao;
	}
	// </editor-fold>

	/**
	 * Authorizator DAO getter
	 * @author Petr Besir Horáček <sirbesir@gmail.com>
	 * @return \Security\AuthorizatorDao
	 */
	private function getAuthorizatorDao()
	{
		return $this->authorizatorDao;
	}
}