<?php
namespace Medienreaktor\AuthChain\Security;

use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;

class TestAuthMiddleware extends AbstractAuthMiddleware {

    public function canReadNodesFromWorkspace(WorkspaceName $workspaceName,  Privilege $currentPrivilege,callable $next): \Neos\ContentRepository\Core\Feature\Security\Dto\Privilege {
        return Privilege::granted("granted");
    }
}
