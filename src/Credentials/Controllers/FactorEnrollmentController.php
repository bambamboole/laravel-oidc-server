<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Credentials\Actions\ConfirmFactorEnrollment;
use Bambamboole\LaravelOidc\Server\Credentials\Actions\EnrollFactor;
use Bambamboole\LaravelOidc\Server\Credentials\Actions\RevokeFactor;
use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\Data\EnrollmentOption;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Credentials\FactorRegistry;
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
        private readonly EnrollFactor $enroll,
        private readonly ConfirmFactorEnrollment $confirmEnrollment,
        private readonly RevokeFactor $revoke,
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

        $enrollment = ($this->enroll)(
            $user,
            $this->enrollable($provider),
            $this->requestedOption($request, $provider),
            is_string($name) && $name !== '' ? $name : null,
        );

        return new JsonResponse($this->serialize($enrollment), 201);
    }

    public function confirm(Request $request, string $provider): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $enrollment = $this->factors->findEnrollment($user, $provider, (string) $request->input('enrollment_id'));

        if ($enrollment === null || ! ($this->confirmEnrollment)($user, $enrollable, $enrollment, $request->except('enrollment_id'))) {
            throw ValidationException::withMessages(['code' => __('The provided two factor authentication code was invalid.')]);
        }

        return new JsonResponse('', 200);
    }

    public function destroy(Request $request, string $provider, string $enrollment): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $pending = $this->factors->findEnrollment($user, $provider, $enrollment) ?? abort(404);

        ($this->revoke)($user, $enrollable, $pending);

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
