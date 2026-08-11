<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Auth\Controllers\AuthenticatedSessionController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\DiscoveryController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\JwksController;
use Bambamboole\LaravelOidc\Server\Http\ProviderMetadata;
use Bambamboole\LaravelOidc\Server\Issuer;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
use Bambamboole\LaravelOidc\Server\Routing\HandlerConfig;
use Bambamboole\LaravelOidc\Server\Routing\HandlerRegistrar;
use Illuminate\Events\Dispatcher;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

/**
 * Registers the configured handlers into a fresh, isolated router so we can
 * inspect the result without the routes already bound during boot.
 */
function registerHandlersInFreshRouter(): Router
{
    $router = new Router(new Dispatcher, app());
    Route::swap($router);

    app(HandlerRegistrar::class)->register();

    // Names are applied fluently after each route is added, so rebuild the
    // name lookup the same way the request lifecycle does before matching.
    $router->getRoutes()->refreshNameLookups();

    return $router;
}

it('registers the OIDC oauth endpoints under the configured passport.path prefix', function () {
    $uri = Route::getRoutes()->getByName('oidc.userinfo')->uri();
    expect($uri)->toStartWith(config('passport.path', 'oauth').'/');
});

it('authenticates userinfo via the configured oidc.api_guard', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    Passport::actingAs($user, ['openid'], 'oidc');

    expect(config('oidc.api_guard'))->toBe('oidc');
    $this->getJson('/oauth/userinfo')->assertOk();
});

it('registers a route for every enabled handler', function () {
    config(['oidc.handlers' => [], 'oidc.dcr.enabled' => true]);

    $routes = registerHandlersInFreshRouter()->getRoutes();

    foreach (Handler::cases() as $handler) {
        expect($routes->getByName($handler->value))->not->toBeNull();
    }
});

it('registers each handler with its intrinsic method', function () {
    $routes = registerHandlersInFreshRouter()->getRoutes();

    expect($routes->getByName(Handler::Login->value)->methods())->toContain('GET')
        ->and($routes->getByName(Handler::LoginStore->value)->methods())->toContain('POST')
        ->and($routes->getByName(Handler::Userinfo->value)->methods())->toContain('GET', 'POST')
        ->and($routes->getByName(Handler::Deny->value)->methods())->toContain('DELETE');
});

it('carries the configured middleware onto the registered route', function () {
    $routes = registerHandlersInFreshRouter()->getRoutes();

    expect($routes->getByName(Handler::LoginStore->value)->middleware())->toContain('throttle:5,1')
        ->and($routes->getByName(Handler::VerificationVerify->value)->middleware())->toContain('signed');
});

it('does not register a handler set to false', function () {
    $handlers = config('oidc.handlers');
    $handlers[Handler::Userinfo->value] = false;
    config(['oidc.handlers' => $handlers]);

    $routes = registerHandlersInFreshRouter()->getRoutes();

    expect($routes->getByName(Handler::Userinfo->value))->toBeNull()
        ->and($routes->getByName(Handler::Jwks->value))->not->toBeNull();
});

it('applies a custom route path, controller and middleware override', function () {
    config([
        'oidc.handlers' => [
            Handler::Login->value => [
                'route' => 'signin',
                'controller' => JwksController::class,
                'middleware' => ['web', 'my-guard'],
            ],
        ],
    ]);

    $route = registerHandlersInFreshRouter()->getRoutes()->getByName(Handler::Login->value);

    expect($route->uri())->toBe('signin')
        ->and($route->getActionName())->toBe(JwksController::class)
        ->and($route->middleware())->toBe(['web', 'my-guard']);
});

it('merges sparse route and controller overrides over handler defaults', function () {
    config([
        'oidc.handlers' => [
            Handler::Login->value => ['route' => 'signin'],
            Handler::Jwks->value => ['controller' => AuthenticatedSessionController::class],
        ],
    ]);

    $login = Handler::Login->config();
    $jwks = Handler::Jwks->config();

    expect($login)->toBeInstanceOf(HandlerConfig::class)
        ->and($login->route)->toBe('signin')
        ->and($login->controller)->toBe([AuthenticatedSessionController::class, 'create'])
        ->and($login->middleware)->toBe(['web', 'guest:identity'])
        ->and($jwks)->toBeInstanceOf(HandlerConfig::class)
        ->and($jwks->route)->toBe('.well-known/jwks.json')
        ->and($jwks->controller)->toBe(AuthenticatedSessionController::class)
        ->and($jwks->middleware)->toBe([]);
});

it('replaces default middleware in a per-handler override', function () {
    config([
        'oidc.handlers' => [
            Handler::LoginStore->value => ['middleware' => ['custom-handler']],
        ],
    ]);

    $config = Handler::LoginStore->config();

    expect($config)->toBeInstanceOf(HandlerConfig::class)
        ->and($config->middleware)->toBe(['custom-handler']);
});

it('appends global route middleware after each handler middleware list', function () {
    config([
        'oidc.routes.middleware' => ['global-one', 'global-two'],
        'oidc.handlers' => [
            Handler::LoginStore->value => ['middleware' => ['handler-only']],
        ],
    ]);

    $routes = registerHandlersInFreshRouter()->getRoutes();

    expect($routes->getByName(Handler::LoginStore->value)->middleware())
        ->toBe(['handler-only', 'global-one', 'global-two'])
        ->and($routes->getByName(Handler::Discovery->value)->middleware())
        ->toBe(['global-one', 'global-two']);
});

it('prefixes every route except the well-known documents and advertises the registered prefixed endpoints', function () {
    config([
        'oidc.issuer' => 'https://issuer.test',
        'oidc.routes.prefix' => 'provider',
        'oidc.handlers' => [],
        'oidc.dcr.enabled' => true,
    ]);

    $wellKnown = [Handler::Discovery, Handler::AuthorizationServerMetadata, Handler::ProtectedResource];

    $routes = registerHandlersInFreshRouter()->getRoutes();
    app('url')->setRoutes($routes);

    expect($routes->getByName(Handler::Discovery->value)->uri())
        ->toBe('.well-known/openid-configuration');

    foreach ($wellKnown as $handler) {
        expect($routes->getByName($handler->value)->uri())->toStartWith('.well-known/');
    }

    foreach (Handler::cases() as $handler) {
        if (in_array($handler, $wellKnown, true)) {
            continue;
        }

        expect($routes->getByName($handler->value)->uri())->toStartWith('provider/');
    }

    $document = app(DiscoveryController::class)(app(ProviderMetadata::class))->getData(true);

    foreach ([
        'authorization_endpoint' => Handler::Authorize,
        'token_endpoint' => Handler::IssueToken,
        'jwks_uri' => Handler::Jwks,
        'userinfo_endpoint' => Handler::Userinfo,
        'end_session_endpoint' => Handler::Logout,
        'introspection_endpoint' => Handler::Introspect,
        'revocation_endpoint' => Handler::Revoke,
        'registration_endpoint' => Handler::ClientRegistration,
    ] as $documentKey => $handler) {
        expect(parse_url($document[$documentKey], PHP_URL_PATH))
            ->toBe('/'.$routes->getByName($handler->value)->uri());
    }
});

it('exposes a handler config DTO through the handler enum', function () {
    config(['oidc.handlers' => []]);

    $config = Handler::Login->config();

    expect($config)->toBeInstanceOf(HandlerConfig::class)
        ->and($config->route)->toBe('auth/login')
        ->and($config->controller)->toBe([AuthenticatedSessionController::class, 'create'])
        ->and($config->middleware)->toBe(['web', 'guest:identity']);
});

it('exposes each handler full default independently of consumer configuration', function () {
    config([
        'oidc.handlers' => [
            Handler::Login->value => false,
        ],
    ]);

    $defaults = Handler::Login->defaults();

    expect($defaults->route)->toBe('auth/login')
        ->and($defaults->controller)->toBe([AuthenticatedSessionController::class, 'create'])
        ->and($defaults->middleware)->toBe(['web', 'guest:identity']);
});

it('returns false for a disabled handler', function () {
    $handlers = config('oidc.handlers');
    $handlers[Handler::Userinfo->value] = false;
    config(['oidc.handlers' => $handlers]);

    expect(Handler::Userinfo->config())->toBeFalse();
});

it('exposes the issuer url', function () {
    config(['oidc.issuer' => 'https://id.example.com/']);

    expect(Issuer::url())->toBe('https://id.example.com');
});
