<?php
namespace Medienreaktor\AuthChain\Security;

use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;

class Test2AuthMiddleware extends AbstractAuthMiddleware {

    public function canReadNodesFromWorkspace(WorkspaceName $workspaceName, Privilege $currentPrivilege, callable $next): Privilege {
        return Privilege::denied("denied");
    }
}
