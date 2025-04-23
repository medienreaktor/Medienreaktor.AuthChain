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

    #[InjectConfiguration(path: "chain")]
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
        $this->contentRepositoryAuthProvider = new ContentRepositoryAuthProvider(
            $this->contentRepositoryId,
            $this->userService,
            $this->contentGraphReadModel,
            $this->authorizationService,
            $this->securityContext
        );
    }

    public function canReadNodesFromWorkspace(WorkspaceName $workspaceName): Privilege {
        return $this->executeMiddlewareChain(
            initialValue: Privilege::granted(""),
            providerCallback: fn() => $this->contentRepositoryAuthProvider->canReadNodesFromWorkspace($workspaceName),
            middlewareCallback: fn($middleware, $currentValue, $next) => $middleware->canReadNodesFromWorkspace($workspaceName, $currentValue, $next)
        );
    }

    public function getVisibilityConstraints(WorkspaceName $workspaceName): VisibilityConstraints {
        return $this->executeMiddlewareChain(
            initialValue: VisibilityConstraints::createEmpty(),
            providerCallback: fn() => $this->contentRepositoryAuthProvider->getVisibilityConstraints($workspaceName),
            middlewareCallback: fn($middleware, $currentValue, $next) => $middleware->getVisibilityConstraints($workspaceName, $currentValue, $next)
        );
    }

    public function canExecuteCommand(CommandInterface $command): Privilege {
        return $this->executeMiddlewareChain(
            initialValue: Privilege::granted(""),
            providerCallback: fn() => $this->contentRepositoryAuthProvider->canExecuteCommand($command),
            middlewareCallback: fn($middleware, $currentValue, $next) => $middleware->canExecuteCommand($command, $currentValue, $next)
        );
    }

    public function getAuthenticatedUserId(): ?UserId {
        return $this->executeMiddlewareChain(
            initialValue: null,
            providerCallback: fn() => $this->contentRepositoryAuthProvider->getAuthenticatedUserId(),
            middlewareCallback: fn($middleware, $currentValue, $next) => $middleware->getAuthenticatedUserId($currentValue, $next)
        );
    }

    private function executeMiddlewareChain(mixed $initialValue, callable $providerCallback, callable $middlewareCallback): mixed {
        $chain = $this->initializeMiddlewareChain();

        $next = function($currentValue) use ($providerCallback){
            return $providerCallback();
        };

        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $middleware = $chain[$i];
            $currentNext = $next;
            $next = fn($currentValue) => $middlewareCallback($middleware, $currentValue, $currentNext);
        }

        return $next($initialValue);
    }

    private function initializeMiddlewareChain(): array {
        $middlewareConfigurations = [];

        foreach ($this->chainConfiguration as $key => $config) {
            $middlewareConfigurations[] = [
                'key' => $key,
                'position' => $config['position'] ?? 0,
                'class' => $config['class']
            ];
        }

        usort($middlewareConfigurations, function ($a, $b) {
            return $a['position'] <=> $b['position'];
        });

        $middlewareClasses = [];
        foreach ($middlewareConfigurations as $config) {
            $object = $this->objectManager->get($config['class']);
            $middlewareClasses[] = $object;
        }


        return array_reverse($middlewareClasses);
    }
}
