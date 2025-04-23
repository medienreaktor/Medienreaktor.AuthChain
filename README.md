# Medienreaktor.AuthChain

This package provides a middleware chain for the content repository authorization.
This is necessary so multiple packages can overwrite the authorization of the content repository without overwriting each other.

## Installation

```shell
composer require medienreaktor/neos-auth-chain
```

## Usage

You can create a new auth provider by extending the `AbstractChainableAuthProvider`:
```php
<?php

namespace Medienreaktor\AuthChain\Security;

use Neos\ContentRepository\Core\CommandHandler\CommandInterface;
use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\Feature\Security\Dto\UserId;
use Neos\ContentRepository\Core\Projection\ContentGraph\VisibilityConstraints;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;

class TestAuthChainable extends AbstractChainableAuthProvider {

    public function canReadNodesFromWorkspace(WorkspaceName $workspaceName, Privilege $currentValue, callable $next): Privilege {
        if($someCondition) {
            return Privilege::granted("reason");
        }
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
```

You can either return a value like ```Privilege::granted("reason");``` or return
```$next($value)``` to call the next part of the auth chain.

If there is no next part of the chain, the default auth provider of the content repository will be used.
## Configuration

### Register the middleware

```yaml
Medienreaktor:
  AuthChain:
    chain:
      'Medienreaktor.AuthChain:Test1':
        class: Medienreaktor\AuthChain\Security\TestAuthChainable2
        position: 3000
      'Medienreaktor.AuthChain:Test2':
        class: Medienreaktor\AuthChain\Security\TestAuthChainable
        position: 'after Medienreaktor.AuthChain:Test1'
```
