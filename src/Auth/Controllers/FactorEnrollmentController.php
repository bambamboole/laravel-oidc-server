<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\EnrollmentPolicy;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorResponse;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

/**
 * The provider-keyed enrollment surface: any registered
 * {@see EnrollableFactorProvider} is enrollable through these endpoints
 * without package changes, including multi-step ceremonies (webauthn returns
 * its creation options in the begin metadata and takes the attestation
 * credential on confirm).
 */
class FactorEnrollmentController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly EnrollmentPolicy $policy,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $user = $this->requireUser($request);

        return new JsonResponse([
            'factors' => array_map(
                $this->serialize(...),
                $this->factors->enrollments($user),
            ),
        ]);
    }

    public function store(Request $request, string $provider): JsonResponse
    {
        $user = $this->requireUser($request);
        $name = $request->input('name');

        $enrollment = $this->enrollable($provider)->beginEnrollment(
            $user,
            is_string($name) && $name !== '' ? $name : null,
        );

        return new JsonResponse($this->serialize($enrollment), 201);
    }

    public function confirm(Request $request, string $provider): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $enrollment = $this->pendingEnrollment($enrollable, $user, (string) $request->input('enrollment_id'));

        $confirmed = $enrollment !== null && $enrollable->confirmEnrollment(
            $user,
            $enrollment,
            new FactorResponse($request->except('enrollment_id')),
        );

        if (! $confirmed) {
            throw ValidationException::withMessages(['code' => __('The provided two factor authentication code was invalid.')]);
        }

        $this->policy->factorConfirmed($user);

        return new JsonResponse('', 200);
    }

    public function destroy(Request $request, string $provider, string $enrollment): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $pending = $this->pendingEnrollment($enrollable, $user, $enrollment);

        if ($pending === null) {
            abort(404);
        }

        $enrollable->revoke($user, $pending);
        $this->policy->factorRevoked($user);

        return new JsonResponse('', 204);
    }

    private function enrollable(string $provider): EnrollableFactorProvider
    {
        return $this->factors->enrollable($provider) ?? abort(404);
    }

    private function requireUser(Request $request): Authenticatable
    {
        return $this->currentUser($request) ?? abort(401);
    }

    private function pendingEnrollment(EnrollableFactorProvider $provider, Authenticatable $user, string $id): ?FactorEnrollment
    {
        foreach ($provider->enrollments($user) as $enrollment) {
            if ($enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    private function serialize(FactorEnrollment $enrollment): array
    {
        return [
            'provider' => $enrollment->providerKey,
            'id' => $enrollment->id,
            'label' => $enrollment->label,
            'confirmed_at' => $enrollment->confirmedAt?->format(DATE_ATOM),
            'last_used_at' => $enrollment->lastUsedAt?->format(DATE_ATOM),
            'metadata' => $enrollment->metadata,
        ];
    }
}
