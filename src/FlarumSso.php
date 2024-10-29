<?php

namespace burnthebook\craftflarumsso;

use Craft;
use yii\base\Event;
use yii\log\Logger;
use craft\base\Model;
use Psr\Log\LogLevel;
use craft\base\Plugin;
use yii\web\UserEvent;
use craft\elements\User;
use craft\events\ModelEvent;
use craft\helpers\UrlHelper;
use craft\log\MonologTarget;
use craft\web\User as WebUser;
use craft\events\FindLoginUserEvent;
use Monolog\Formatter\LineFormatter;
use craft\controllers\UsersController;
use burnthebook\craftflarumsso\models\Settings;
use burnthebook\craftflarumsso\services\FlarumApiClient;

/**
 * Flarum SSO for Craft 4 plugin
 *
 * @method static FlarumSso getInstance()
 * @method Settings getSettings()
 * @author Burnthebook <support@burnthebook.co.uk>
 * @copyright Burnthebook
 * @license MIT
 *
 * @property Settings $settings
 */
class FlarumSso extends Plugin
{
    public string $schemaVersion = '1.0.0';
    public bool $hasCpSettings = true;

    public static function config(): array
    {
        return [
            'components' => [
                // Define component configs here...
            ],
        ];
    }

    public function init(): void
    {
        parent::init();

        // Register a custom log target, keeping the format as simple as possible.
        Craft::getLogger()->dispatcher->targets[] = new MonologTarget([
            'name' => 'flarum-sso',
            'categories' => ['flarum-sso'],
            'level' => LogLevel::INFO,
            'logContext' => false,
            'allowLineBreaks' => false,
            'formatter' => new LineFormatter(
                format: "%datetime% %message%\n",
                dateFormat: 'Y-m-d H:i:s',
            ),
        ]);

        // Defer most setup tasks until Craft is fully initialized
        Craft::$app->onInit(function () {
            if (!Craft::$app->request->isConsoleRequest) {
                $this->attachEventHandlers();
            }
            // ...
        });
    }

    protected function createSettingsModel(): ?Model
    {
        return Craft::createObject(Settings::class);
    }

    protected function settingsHtml(): ?string
    {
        return Craft::$app->view->renderTemplate('flarum-sso/_settings.twig', [
            'plugin' => $this,
            'settings' => $this->getSettings(),
        ]);
    }

    private function attachEventHandlers(): void
    {
        // Register event handlers here ...
        // (see https://craftcms.com/docs/4.x/extend/events.html to get started)

        // API Client Options
        $options = [
            'endpoint' => $this->settings->flarumApiUrl,
            'api_key' => $this->settings->flarumApiKey,
            'cookie_options' => [
                'domain' => $this->settings->flarumCookieDomain,
                'prefix' => $this->settings->flarumCookiePrefix ?? 'flarum_', // optional
                'http_only' => $this->settings->flarumCookieHttpOnly ?? true, // optional
                'path' => $this->settings->flarumCookiePath ?? '/', // optional
                'same_site' => $this->settings->flarumCookieSameSite ?? 'lax', // optional
                'secure_only' => $this->settings->flarumCookieSecureOnly ?? false, // optional
            ]
        ];

        // Don't break requests if the plugin is not configured
        if (!$this->settings->flarumApiUrl || !$this->settings->flarumApiKey) {
            return;
        }

        // Init client
        $client = new FlarumApiClient(
            endpoint: $options['endpoint'],
            apiKey: $options['api_key'],
            cookieOptions: $options['cookie_options']
        );

        // Get redirect URL
        $redirect = Craft::$app->request->getParam('redirect');

        /**
         * On login, log user into flarum too
         */
        Event::on(
            UsersController::class,
            UsersController::EVENT_AFTER_FIND_LOGIN_USER,
            function (FindLoginUserEvent $event) use ($client, $redirect) {
                // Check we actually authenticated with Craft
                if ($event->user) {
                    $craftUser = [
                        'username' => $this->getFlarumUsername($event->user),
                        'email' => $event->user->email,
                        'password' => $this->getFlarumPassword(),
                    ];

                    if ($this->settings->emailUsernames) {
                        $craftUser['nickname'] = $event->user->fullName;
                    }

                    // Check if user exists on Flarum
                    $flarumUser = $client->getUserByName($craftUser['username']);
                    if (($flarumUser['error'] == false) && ($flarumUser['data']->data->id)) {
                        if (
                            ($this->settings->emailUsernames && $flarumUser['data']->data->attributes->displayName !== $craftUser['nickname']) ||
                            $flarumUser['data']->data->attributes->email !== $craftUser['email']
                        ) {
                            $client->updateUser($craftUser, $flarumUser['data']->data->id);
                        }

                        $this->login(client: $client, user: $craftUser);
                    } else {
                        // otherwise sign them up
                        $this->signup(client: $client, user: $craftUser);
                    }

                    // redirect if set
                    if ($redirect) {
                        Craft::$app->getResponse()->redirect(UrlHelper::url($redirect))->send();
                    }
                }
            }
        );

        /**
         * On user save, update info if needed
         */
        Event::on(
            User::class,
            User::EVENT_AFTER_SAVE,
            function (ModelEvent $event) use ($client) {
                /** @var User $user */
                $user = $event->sender;

                $craftUser = [
                    'username' => $this->getFlarumUsername($user),
                    'email' => $user->email,
                    'password' => $this->getFlarumPassword(),
                ];

                if ($this->settings->emailUsernames) {
                    $craftUser['nickname'] = $user->fullName;
                }

                $flarumUser = $client->getUserByName($craftUser['username']);
                if (($flarumUser['error'] == false) && ($flarumUser['data']->data->id)) {
                    $flarumUserAttributes = $flarumUser['data']->data->attributes;

                    if (
                        ($this->settings->emailUsernames && $flarumUserAttributes->displayName !== $craftUser['nickname']) ||
                        $flarumUserAttributes->email !== $craftUser['email']
                    ) {
                        $client->updateUser($craftUser, $flarumUser['data']->data->id);
                    }
                }
            }
        );

        /**
         * On logout, log the user out of Flarum by deleting session cookies
         */
        Event::on(
            \craft\web\User::class,
            WebUser::EVENT_AFTER_LOGOUT,
            function (UserEvent $event) use ($client, $redirect) {
                // Log the user out
                $this->logout(client: $client);

                // redirect if set
                if ($redirect) {
                    Craft::$app->getResponse()->redirect(UrlHelper::url($redirect))->send();
                }
            }
        );
    }

    /**
     * Log the user into Flarum with their Craft Credentials
     *
     * @param \burnthebook\craftflarumsso\services\FlarumApiClient $client An instance of the Flarum API Client
     * @param array $user The Craft CMS User Data
     *
     * @return void
     */
    protected function login(FlarumApiClient $client, array $user): void
    {
        try {
            // Get token
            $token = $client->getToken(
                username: $user['username'],
                password: $user['password'],
            );

            // getToken returns an array if error.
            if ($token['error']) {
                throw new \Exception('Authentication failed: ' . $token['data']);
            }

            // Set session cookie
            $client->setCookie(
                name: 'token',
                payload: $token['data']->token
            );

            // Set remember cookie
            $client->setCookie(
                name: 'remember',
                payload: $token['data']->token,
                longLived: true
            );
        } catch (\Exception $e) {
            Craft::getLogger()->log("Flarum Authentication Failed." . " \r\nException: " . $e->getMessage() . " \r\n This is likely because the passwords in Flarum and Craft do not match.", Logger::LEVEL_INFO, 'flarum-sso');
        }
    }

    /**
     * Log the user out
     *
     * @param \burnthebook\craftflarumsso\services\FlarumApiClient $client An instance of the Flarum API Client
     *
     * @return  void
     */
    protected function logout(FlarumApiClient $client): void
    {
        $client->deleteCookie('token');
        $client->deleteCookie('remember');
    }

    /**
     * Sign the user up to Flarum with their Craft Credentials
     *
     * @param \burnthebook\craftflarumsso\services\FlarumApiClient $client An instance of the Flarum API Client
     * @param array $user The Craft CMS User Data
     *
     * @return void
     */
    protected function signup(FlarumApiClient $client, array $user): void
    {
        // Create account
        $client->createAccount(userDetails: $user);

        // Log account in
        $this->login($client, $user);
    }

    protected function getFlarumUsername(User $user): string
    {
        if ($this->settings->emailUsernames) {
            return 'user' . $user->id;
        }

        return $user->username;
    }

    protected function getFlarumPassword(): string
    {
        return md5($this->settings->flarumApiKey);
    }
}
