<?php
namespace Medienreaktor\AuthChain\Security;


use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;

abstract class AbstractAuthMiddleware {

    abstract public function canReadNodesFromWorkspace(WorkspaceName $workspaceName, Privilege $currentPrivilege, callable $next): Privilege;

}
