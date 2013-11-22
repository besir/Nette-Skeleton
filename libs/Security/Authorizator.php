<?php

namespace Security;

/**
 * Dinamic database authorizator
 *
 * Petr Besir Horáček <sirbesir@gmail.com>
 */
class Authorizator extends \Nette\Security\Permission
{

	/** @var \Security\AuthorizatorService $authorizatorService */
	private $authorizatorService;

	private $roles;

	private $rules;

	private $resources;

	public function __construct(\Security\AuthorizatorService $authorizatorService)
	{
		$this->injectAuthorizatorService($authorizatorService);
	}

	// <editor-fold defaultstate="collapsed" desc="Dependency Injection">
	/**
	 * Authorizator service injection
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @param \Security\AuthorizatorService $authorizatorService
	 */
	public function injectAuthorizatorService(\Security\AuthorizatorService $authorizatorService)
	{
		if ($this->authorizatorService !== NULL)
		{
			throw new \Nette\InvalidStateException('Authorizator Service has already been set');
		}
		$this->authorizatorService = $userService;
	}
	// </editor-fold>

	/**
	 * Authorizator service getter
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @return \Security\AuthorizatorService
	 */
	public function getAuthorizatorService()
	{
		return $this->authorizatorService;
	}
}