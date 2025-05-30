<?php

declare(strict_types=1);

namespace Medienreaktor\AuthChain\Security;

use Neos\ContentRepository\Core\Projection\ContentGraph\ContentGraphReadModelInterface;
use Neos\ContentRepository\Core\SharedModel\ContentRepository\ContentRepositoryId;
use Neos\ContentRepositoryRegistry\Factory\AuthProvider\AuthProviderFactoryInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Neos\Domain\Service\UserService;
use Neos\Neos\Security\Authorization\ContentRepositoryAuthorizationService;

/**
 * Implementation of the {@see AuthProviderFactoryInterface} in order to provide authentication and authorization for Content Repositories
 *
 * @api
 */
#[Flow\Scope('singleton')]
final readonly class AuthChainAuthProviderFactory implements AuthProviderFactoryInterface
{
    public function __construct(
        private UserService $userService,
        private ContentRepositoryAuthorizationService $contentRepositoryAuthorizationService,
        private SecurityContext $securityContext,
    ) {
    }

    public function build(ContentRepositoryId $contentRepositoryId, ContentGraphReadModelInterface $contentGraphReadModel): AuthChainAuthProvider
    {
        return new AuthChainAuthProvider($contentRepositoryId, $this->userService, $contentGraphReadModel, $this->contentRepositoryAuthorizationService, $this->securityContext);
    }
}
