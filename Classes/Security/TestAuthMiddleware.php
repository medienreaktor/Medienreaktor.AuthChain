<?php

namespace Medienreaktor\AuthChain\Security;

use Neos\ContentRepository\Core\CommandHandler\CommandInterface;
use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\Feature\Security\Dto\UserId;
use Neos\ContentRepository\Core\Projection\ContentGraph\VisibilityConstraints;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;

class TestAuthMiddleware extends AbstractChainableAuthProvider {

    public function canReadNodesFromWorkspace(WorkspaceName $workspaceName, Privilege $currentValue, callable $next): Privilege {
        return $next($currentValue);
    }

    public function getVisibilityConstraints(WorkspaceName $workspaceName, $currentValue, callable $next): VisibilityConstraints {
        return $next($currentValue);
    }

    public function canExecuteCommand(CommandInterface $command, $currentValue, callable $next): Privilege {
        return $next($currentValue);
    }

    public function getAuthenticatedUserId($currentValue, callable $next): ?UserId {
        return $next($currentValue);
    }
}
