<?php
/**
 * Created by PhpStorm.
 * User: ronil23
 * Date: 13/08/15
 * Time: 1:05 PM
 */

namespace AppBundle\Security\User;


use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use GuzzleHttp\Client;
use AppBundle\Security\User\WebserviceUser;

class WebserviceUserProvider implements UserProviderInterface
{

    protected $accountHost;

    public function __construct($accountHost)
    {
        //$this->session = $session;
        $this->accountHost = $accountHost;
        //$this->entityManager = $doctrine->getManager();

    }

    public function loadUserByUsername($profileToken)
    {
        $client = new Client(
            array('base_url' => $this->accountHost,
                'defaults' => array('headers' => array('X-Profile-Token' => $profileToken)))
        );

        $res = $client->get('/get_profile_with_token', ['exceptions' => false]);


        if($res->getStatusCode()===200){
            $userJson = $res->json();
            $userId = $userJson["id"];
        }

        if ($userJson) {
            $username = $userJson["id"];
            $password = $profileToken;
            $roles = array();

            // ...
            return new WebserviceUser($username, $password, $roles);
        }

        throw new UsernameNotFoundException(
            sprintf('Username does not exist.')
        );
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof WebserviceUser) {
            throw new UnsupportedUserException(
                sprintf('Instances of "%s" are not supported.', get_class($user))
            );
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return $class === 'AppBundle\Security\User\WebserviceUser';
    }


}