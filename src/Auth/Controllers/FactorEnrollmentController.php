<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Data\EnrollmentOption;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\EnrollmentPolicy;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorRegistry;
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
        private readonly Auditor $auditor,
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
            $this->requestedOption($request, $provider),
            is_string($name) && $name !== '' ? $name : null,
        );

        $this->auditor->log(AuditEventType::FactorEnrollmentStarted, userId: (string) $user->getAuthIdentifier(), context: [
            'factor' => $provider,
            'enrollment_id' => $enrollment->id,
        ]);

        return new JsonResponse($this->serialize($enrollment), 201);
    }

    public function confirm(Request $request, string $provider): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $enrollment = $this->factors->findEnrollment($user, $provider, (string) $request->input('enrollment_id'));

        if ($enrollment === null || ! $enrollable->confirmEnrollment($user, $enrollment, $request->except('enrollment_id'))) {
            throw ValidationException::withMessages(['code' => __('The provided two factor authentication code was invalid.')]);
        }

        $this->policy->factorConfirmed($user);

        $this->auditor->log(AuditEventType::FactorConfirmed, userId: (string) $user->getAuthIdentifier(), context: [
            'factor' => $provider,
            'enrollment_id' => $enrollment->id,
        ]);

        return new JsonResponse('', 200);
    }

    public function destroy(Request $request, string $provider, string $enrollment): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $pending = $this->factors->findEnrollment($user, $provider, $enrollment) ?? abort(404);

        $enrollable->revoke($user, $pending);
        $this->policy->factorRevoked($user);

        $this->auditor->log(AuditEventType::FactorRevoked, userId: (string) $user->getAuthIdentifier(), context: [
            'factor' => $provider,
            'enrollment_id' => $enrollment,
        ]);

        return new JsonResponse('', 204);
    }

    private function enrollable(string $provider): EnrollableFactorProvider
    {
        return $this->factors->enrollable($provider) ?? abort(404);
    }

    /**
     * The enrollment option the caller picked. Optional — omitting it keeps the
     * provider's default — but an option that belongs to a different provider is
     * a client bug, not a fallback.
     */
    private function requestedOption(Request $request, string $provider): ?EnrollmentOption
    {
        $id = $request->input('option');

        if (! is_string($id) || $id === '') {
            return null;
        }

        $option = $this->factors->enrollmentOption($id);

        if ($option === null || $option->providerKey !== $provider) {
            throw ValidationException::withMessages(['option' => __('The selected enrollment option is invalid.')]);
        }

        return $option;
    }

    private function requireUser(Request $request): Authenticatable
    {
        return $this->currentUser($request) ?? abort(401);
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
