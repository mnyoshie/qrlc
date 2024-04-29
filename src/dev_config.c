#include <stdlib.h>

#include "include/types.h"
#include "dev_config.h"

const char *qget_mainnet_address(qu32 i) {
  if (i > 2)
    return NULL;

  const char *const mainnet_addrs[] = {
    QRL_MAINNET1,
    QRL_MAINNET2,
    NULL
  };

  return mainnet_addrs[i];
}

/* self.hard_fork_heights = [942375, 1938000, 2078800] */
qu64 qget_hardfork_height(qu64 i) {
 if (i > 3)
   return 0;

  const qu64 hardfork_height[] = {
    QRL_HARD_FORK_HEIGHT0,
    QRL_HARD_FORK_HEIGHT1,
    QRL_HARD_FORK_HEIGHT2
  };

  return hardfork_height[i];
}

const qvec_t *qget_banned_address(qu64 i) {
  if (i > 1)
    return NULL;

  const qvec_t *banned_address = {
    &QRL_BANNED_ADDRESS1
  };

  return banned_address + i;
}
