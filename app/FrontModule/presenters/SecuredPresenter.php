<?php

namespace FrontModule;

use \Nette\Security\User;

/**
 * SecuredPresenter
 * @author Petr Besir Horáček <sirbesir@gmail.com>
 */
abstract class SecuredPresenter extends \FrontModule\FrontPresenter
{

	/**
	 * Startup
	 * @author Petr Besir Horacek <sirbesir@gmail.com>
	 * @see Nette\Application\Presenter#startup()
	 */
	public function startup()
	{
		parent::startup();
		$user = $this->getUser();
		if (FALSE === $user->isLoggedIn())
		{
			if ($user->getLogoutReason() === User::INACTIVITY)
			{
				$this->flashMessage('Byl jste dlouho nečinný, systém Vás kvůli bezpečnosti odhlásil.');
			}

			$backlink = $this->getApplication()->storeRequest();
			$this->redirect('Sign:in', array('backlink' => $backlink));
		}
		else
		{
			if (FALSE === $user->isAllowed($this->name, $this->action))
			{
				$this->flashMessage('Nemáte dostatečná práva pro tuto akci!', 'error');
				$this->redirect('Homepage:');
			}
		}
	}

}