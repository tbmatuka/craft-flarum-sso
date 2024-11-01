<?php

namespace tbmatuka\craftflarumsso\models;

use Craft;
use craft\behaviors\EnvAttributeParserBehavior;
use craft\helpers\App;
use craft\base\Model;

/**
 * Flarum SSO for Craft 4 settings
 */
class Settings extends Model
{
    /**
     * Flarum API URL (Required)
     * @var string
     */
    public string $flarumApiUrl = '';

    /**
     * Flarum API Key (Required)
     * @var string
     */
    public string $flarumApiKey = '';

    /**
     * Email Usernames
     * @var bool
     */
    public bool $emailUsernames = false;

    /**
     * Flarum Cookie - Domain (Required)
     * @var string
     */
    public string $flarumCookieDomain = '';

    /**
     * Flarum Cookie - HTTP Only?
     * @var bool
     */
    public bool $flarumCookieHttpOnly = true;

    /**
     * Flarum Cookie - Secure Only?
     * @var bool
     */
    public bool $flarumCookieSecureOnly = false;

    /**
     * Flarum Cookie - Prefix
     * @var string
     */
    public string $flarumCookiePrefix = 'flarum_';

    /**
     * Flarum Cookie - Path
     * @var string
     */
    public string $flarumCookiePath = '/';

    /**
     * Flarum Cookie - Same Site
     * @var string
     */
    public string $flarumCookieSameSite = 'lax';

    /**
     * @return array
     */
    public function defineRules(): array
    {
        return [
            [
                [
                    'flarumApiUrl',
                    'flarumApiKey',
                    'flarumCookieDomain',
                ],
                'required',
            ],
            [
                [
                    'emailUsernames',
                    'flarumCookieHttpOnly',
                    'flarumCookieSecureOnly',
                ],
                'boolean',
            ],
            [
                [
                    'flarumCookiePrefix',
                    'flarumCookiePath',
                    'flarumCookieSameSite',
                ],
                'string',
            ],
        ];
    }

    public function defineBehaviors(): array
    {
        return [
            'parser' => [
                'class' => EnvAttributeParserBehavior::class,
                'attributes' => ['flarumApiUrl', 'flarumApiKey', 'flarumCookieDomain'],
            ],
        ];
    }

    public function getFlarumApiUrl(): string
    {
        return App::parseEnv($this->flarumApiUrl);
    }

    public function getFlarumApiKey(): string
    {
        return App::parseEnv($this->flarumApiKey);
    }

    public function getFlarumCookieDomain(): string
    {
        return App::parseEnv($this->flarumCookieDomain);
    }
}
