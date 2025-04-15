<?php

namespace Medienreaktor\AuthChain\Security;

use Neos\ContentRepository\Core\CommandHandler\CommandInterface;
use Neos\ContentRepository\Core\Feature\Security\AuthProviderInterface;
use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\Feature\Security\Dto\UserId;
use Neos\ContentRepository\Core\Projection\ContentGraph\ContentGraphReadModelInterface;
use Neos\ContentRepository\Core\Projection\ContentGraph\VisibilityConstraints;
use Neos\ContentRepository\Core\SharedModel\ContentRepository\ContentRepositoryId;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Annotations\InjectConfiguration;
use Neos\Flow\ObjectManagement\ObjectManager;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Neos\Domain\Service\UserService;
use Neos\Neos\Security\Authorization\ContentRepositoryAuthorizationService;
use Neos\Neos\Security\ContentRepositoryAuthProvider\ContentRepositoryAuthProvider;

class AuthChainAuthProvider implements AuthProviderInterface {

    protected ContentRepositoryAuthProvider $contentRepositoryAuthProvider;

    #[InjectConfiguration(path: "chain", package: "Medienreaktor.AuthChain")]
    protected $chainConfiguration;

    #[Inject]
    protected ObjectManager $objectManager;

    public function __construct(
        private ContentRepositoryId                   $contentRepositoryId,
        private UserService                           $userService,
        private ContentGraphReadModelInterface        $contentGraphReadModel,
        private ContentRepositoryAuthorizationService $authorizationService,
        private SecurityContext                       $securityContext,
    ) {
        $this->contentRepositoryAuthProvider = new ContentRepositoryAuthProvider($this->contentRepositoryId, $this->userService, $this->contentGraphReadModel, $this->authorizationService, $this->securityContext);
    }

    public function canReadNodesFromWorkspace(WorkspaceName $workspaceName): Privilege {
        $chain = $this->initializeMiddlewareChain();
        $privilege = Privilege::granted("");

        $next = function (Privilege $prevPrivilege) use ($workspaceName) {
            return $this->contentRepositoryAuthProvider->canReadNodesFromWorkspace($workspaceName);
        };

        for ($i = count($chain) - 1; $i >= 0; $i--) {
            /** @var AbstractAuthMiddleware $middleware */
            $middleware = $chain[$i];

            $next = function (Privilege $currentPrivilege) use ($middleware, $next, $workspaceName) {
                return $middleware->canReadNodesFromWorkspace($workspaceName, $currentPrivilege, $next);
            };

        }

        return $next($privilege);
    }

    private function initializeMiddlewareChain(): array {
        $middlewareKeys = array_keys($this->chainConfiguration);

        $middlewareClasses = [];

        foreach ($middlewareKeys as $middlewareKey) {
            $middleware = $this->chainConfiguration[$middlewareKey];
            $object = $this->objectManager->get($middleware['class']);
            $middlewareClasses[] = $object;
        }

        return array_reverse($middlewareClasses);
    }

    public function getVisibilityConstraints(WorkspaceName $workspaceName): VisibilityConstraints {
        return $this->contentRepositoryAuthProvider->getVisibilityConstraints($workspaceName);
    }

    public function canExecuteCommand(CommandInterface $command): Privilege {
        return $this->contentRepositoryAuthProvider->canExecuteCommand($command);
    }


    public function getAuthenticatedUserId(): ?UserId {
        return $this->contentRepositoryAuthProvider->getAuthenticatedUserId();
    }

}
