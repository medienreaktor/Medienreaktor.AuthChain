<?php

namespace Medienreaktor\AuthChain\Security;

use Neos\ContentRepository\Core\CommandHandler\CommandInterface;
use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\Feature\Security\Dto\UserId;
use Neos\ContentRepository\Core\Projection\ContentGraph\VisibilityConstraints;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;

abstract class AbstractChainableAuthProvider
{
    /**
     * @param WorkspaceName $workspaceName
     * @param Privilege $currentValue
     * @param callable(Privilege): Privilege $next
     * @return Privilege
     */
    abstract public function canReadNodesFromWorkspace(
        WorkspaceName $workspaceName,
        Privilege $currentValue,
        callable $next
    ): Privilege;

    /**
     * @param WorkspaceName $workspaceName
     * @param VisibilityConstraints $currentValue
     * @param callable(VisibilityConstraints): VisibilityConstraints $next
     * @return VisibilityConstraints
     */
    abstract public function getVisibilityConstraints(
        WorkspaceName $workspaceName,
        VisibilityConstraints $currentValue,
        callable $next
    ): VisibilityConstraints;

    /**
     * @param CommandInterface $command
     * @param Privilege $currentValue
     * @param callable(Privilege): Privilege $next
     * @return Privilege
     */
    abstract public function canExecuteCommand(
        CommandInterface $command,
        Privilege $currentValue,
        callable $next
    ): Privilege;

    /**
     * @param UserId|null $currentValue
     * @param callable(?UserId): ?UserId $next
     * @return UserId|null
     */
    abstract public function getAuthenticatedUserId(
        ?UserId $currentValue,
        callable $next
    ): ?UserId;
}
