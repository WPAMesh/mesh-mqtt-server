package components

import "sort"

// SortNodes sorts a slice of NodeData by NodeID (empty IDs first), then by ClientID as tiebreaker
func SortNodes(nodes []NodeData) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].NodeID == "" && nodes[j].NodeID != "" {
			return true
		}
		if nodes[i].NodeID != "" && nodes[j].NodeID == "" {
			return false
		}
		if nodes[i].NodeID != nodes[j].NodeID {
			return nodes[i].NodeID < nodes[j].NodeID
		}
		return nodes[i].ClientID < nodes[j].ClientID
	})
}

// SortMeshCoreClients sorts a slice of MeshCoreClientData by ClientID
func SortMeshCoreClients(clients []MeshCoreClientData) {
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].ClientID < clients[j].ClientID
	})
}

// SortObservers sorts a slice of ObserverClientData by Name then ClientID
func SortObservers(observers []ObserverClientData) {
	sort.Slice(observers, func(i, j int) bool {
		if observers[i].Name != observers[j].Name {
			return observers[i].Name < observers[j].Name
		}
		return observers[i].ClientID < observers[j].ClientID
	})
}

// SortOtherClients sorts a slice of OtherClientData by ClientID
func SortOtherClients(clients []OtherClientData) {
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].ClientID < clients[j].ClientID
	})
}
