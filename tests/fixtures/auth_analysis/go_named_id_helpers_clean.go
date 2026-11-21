// Internal helpers whose id parameters carry a named id type, or a slice or
// map of ids.  The caller already holds the ids, so the helper is not an
// entry point for user input.  Pinned in `auth_analysis_tests`.
package endpoints

import (
	portainer "example.com/portainer/api"

	"example.com/dataservices"
)

func removeEndpoint(tx dataservices.DataStoreTx, endpointID portainer.EndpointID) error {
	return tx.EndpointStore.DeleteEndpoint(endpointID)
}

func removeTargets(tx dataservices.DataStoreTx, ids ...TargetID) error {
	return tx.TargetStore.DeleteTargets(ids)
}

func removeMany(tx dataservices.DataStoreTx, ids []int64, byGroup map[int64]int64) error {
	return tx.EndpointStore.DeleteMany(ids, byGroup)
}
