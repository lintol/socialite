<?php

namespace Laravel\Socialite\Two;

use Exception;
use Illuminate\Support\Arr;

class CkanProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = ['user:email'];

    protected $rootUrl = null;

    public function getRedirectUrl()
    {
        return $this->redirectUrl;
    }

    protected function getRootUrl()
    {
        if ($this->rootUrl) {
            return $this->rootUrl;
        }

        $defaultCkan = config('services.ckan.url', null);

        if ($defaultCkan) {
            return $defaultCkan;
        }

        throw RuntimeException(__("No OAuth2 server defined."));
    }

    public function setRootUrl($rootUrl)
    {
        $this->rootUrl = $rootUrl;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->getRootUrl() . '/oauth2/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->getRootUrl() . '/oauth2/access_token';
    }

    public function getApiKeyByToken($token)
    {
        $user = $this->getUserByToken($token);
        if ($user && array_key_exists('apikey', $user) && $user['apikey']) {
            return $user['apikey'];
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $userUrl = $this->getRootUrl() . '/oauth2/identity?access_token='.$token;

        $response = $this->getHttpClient()->get(
            $userUrl, $this->getRequestOptions()
        );

        $user = json_decode($response->getBody(), true);

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['id'], 'nickname' => $user['login'], 'name' => Arr::get($user, 'name'),
            'email' => Arr::get($user, 'email'), 'avatar' => null,
        ]);
    }

    /**
     * Get the default options for an HTTP request.
     *
     * @return array
     */
    protected function getRequestOptions()
    {
        return [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ];
    }
}
